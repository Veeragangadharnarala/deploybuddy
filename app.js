(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const form = $("#scan-form"), input = $("#source-files"), upload = $("#file-upload");
  const fileName = $("#file-name"), selected = $("#selected-files"), errorBox = $("#scan-error"), results = $("#scan-results"), scanButton = $("#scan-button");
  let files = [];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const sample = `public class ExampleService {
    public void process(String password) {
        System.out.println("Starting service");
        String api_key = "sample-placeholder-value";
        try {
            // TODO: validate incoming input
        } catch (Exception e) { }
    }
}`;
  function renderFiles() {
    selected.innerHTML = files.length ? files.map((f,i)=>`<span class="file-chip">${esc(f.name)} <button type="button" data-remove="${i}" aria-label="Remove file">×</button></span>`).join("") : '<span class="empty-files">No files added yet — paste code or load a sample.</span>';
    selected.querySelectorAll("[data-remove]").forEach(b=>b.addEventListener("click",()=>{const idx=Number(b.dataset.remove);files.splice(idx,1);renderFiles();if(files.length)renderEditor();else{input.value="";fileName.textContent="Example.java";}}));
  }
  function renderEditor() { fileName.textContent = files.length ? files[files.length-1].name : "Example.java"; input.value = files.length ? files[files.length-1].content : ""; }
  function updateCurrentEditor() {
    const name = fileName.textContent || "PastedSource.java";
    if (!files.length) files.push({name,content:input.value});
    else { files[files.length-1].content=input.value; }
    renderFiles();
  }
  $("#load-sample").addEventListener("click",()=>{
    files=[{name:"ExampleService.java",content:sample},{name:"application.properties",content:"server.port=8080\nspring.datasource.url=jdbc:postgresql://localhost:5432/example\n# TODO: configure production environment"}];
    renderFiles();renderEditor();errorBox.hidden=true;results.hidden=true;
  });
  $("#clear-files").addEventListener("click",()=>{files=[];renderFiles();renderEditor();input.value="";upload.value="";results.hidden=true;errorBox.hidden=true;});
  input.addEventListener("input",updateCurrentEditor);
  upload.addEventListener("change",async()=>{
    const chosen=Array.from(upload.files||[]);
    for(const f of chosen){
      if(files.length>=80)break;
      if(f.size>250000){errorBox.textContent=`${f.name} is too large. Please choose a file smaller than 250 KB.`;errorBox.hidden=false;continue;}
      try{files.push({name:f.name,content:await f.text()});}
      catch{errorBox.textContent=`Could not read ${f.name}.`;errorBox.hidden=false;}
    }
    renderFiles();if(files.length)renderEditor();upload.value="";
  });
  const rules = [
    {id:"secret",severity:"critical",category:"Security",title:"Possible hard-coded credential",owner:"DevSecOps / Security",detail:"This line resembles a password, API key, access token, or secret stored directly in code. Pattern matching can produce false positives.",fix:"Move real secrets to a secret manager or environment variable, rotate any exposed credential, and ensure the value is not committed.",verify:"Check the value manually; review repository history and secret-scanning results."},
    {id:"debug",severity:"low",category:"Code hygiene",title:"Debug output in source",owner:"Backend / Development",detail:"Console or print statements may leak details or clutter production logs.",fix:"Use the project's logging framework and appropriate log levels; remove temporary debugging output.",verify:"Run tests and inspect production logging configuration."},
    {id:"todo",severity:"low",category:"Code hygiene",title:"TODO or FIXME marker",owner:"Backend / Development",detail:"A TODO/FIXME marker may indicate unfinished work. It is a reminder, not necessarily a defect.",fix:"Confirm whether the task blocks release; resolve it or create a tracked issue with an owner.",verify:"Review surrounding code and linked issue status."},
    {id:"emptycatch",severity:"medium",category:"Reliability",title:"Empty exception handler",owner:"Backend / Development",detail:"An empty catch/except block can hide failures and make the application appear successful when work failed.",fix:"Handle the expected exception, log useful context without sensitive data, or rethrow it.",verify:"Add a test that exercises the failure path."},
    {id:"http",severity:"medium",category:"Security",title:"Non-HTTPS URL",owner:"DevSecOps / Platform",detail:"An HTTP URL may be intentional for local development, but external traffic can be exposed to interception.",fix:"Use HTTPS for production endpoints unless there is a documented reason not to.",verify:"Confirm the destination and environment-specific configuration."},
    {id:"selectstar",severity:"low",category:"Database",title:"Broad SELECT * query",owner:"Database / Data",detail:"Selecting every column can increase data transfer and couple code to schema changes.",fix:"Select only the columns the application needs, where practical.",verify:"Run query tests and compare the query plan for important paths."},
    {id:"sqlconcat",severity:"high",category:"Security",title:"Possible SQL string concatenation",owner:"Backend / Database / Security",detail:"Building SQL with string concatenation can create SQL injection risk if untrusted input is included.",fix:"Use prepared statements or parameterized queries. Do not assume every concatenation is exploitable.",verify:"Review data flow and add tests for untrusted input."},
    {id:"envfile",severity:"medium",category:"Configuration",title:"Environment or secret file included",owner:"DevSecOps / Platform",detail:"Files named .env or similar may contain environment-specific credentials. This check cannot tell whether values are real secrets.",fix:"Keep local secret files out of version control; commit a safe example file instead.",verify:"Review ignore rules and repository history."},
    {id:"springdebug",severity:"medium",category:"Configuration",title:"Debug or verbose setting",owner:"Platform / DevOps",detail:"A debug/verbose setting may expose excessive details or affect production performance.",fix:"Confirm the setting is appropriate for the target environment and disable unnecessary debug modes in production.",verify:"Review deployment-specific configuration and logs."}
  ];
  function analyzeFile(file) {
    const findings=[], lines=file.content.split(/\r?\n/);
    const add=(rule,lineNo,lineText)=>findings.push({...rule,file:file.name,line:lineNo,confidence:"heuristic",detail:rule.detail+(lineText.trim()?` Matched line: ${lineText.trim().slice(0,180)}`:"")});
    lines.forEach((line,i)=>{
      const n=i+1, t=line.trim();
      if(/\b(password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["'][^"']{4,}["']/i.test(line) && !/sample-placeholder|your[_-].*(key|secret)|example|changeme|<.*>|\$\{/.test(line)) add(rules.find(r=>r.id==="secret"),n,line);
      if(/\b(console\.(log|debug|warn|error)|System\.out\.print|print\s*\(|println\s*\()/i.test(line)) add(rules.find(r=>r.id==="debug"),n,line);
      if(/\b(TODO|FIXME|XXX)\b/i.test(line)) add(rules.find(r=>r.id==="todo"),n,line);
      if(/catch\s*\([^)]*\)\s*\{\s*\}|except\s*[^:]*:\s*(pass)?\s*(#.*)?$/i.test(t) && (/\{\s*\}$/.test(t)||/\bpass\b/.test(t))) add(rules.find(r=>r.id==="emptycatch"),n,line);
      if(/http:\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)/i.test(line)) add(rules.find(r=>r.id==="http"),n,line);
      if(/\bSELECT\s+\*\s+FROM\b/i.test(line)) add(rules.find(r=>r.id==="selectstar"),n,line);
      if(/(SELECT|UPDATE|INSERT|DELETE).*(\+\s*[a-zA-Z_$]|"\s*\+\s*[a-zA-Z_$]|'\s*\+\s*[a-zA-Z_$])/i.test(line)) add(rules.find(r=>r.id==="sqlconcat"),n,line);
      if(/(^|\/)\.env(\.|$)|(^|\/)secrets?\.(json|ya?ml|properties)$/i.test(file.name)) add(rules.find(r=>r.id==="envfile"),n,file.name);
      if(/\b(debug\s*[:=]\s*true|logging\.level\.[\w.]+\s*=\s*debug|spring\.profiles\.active\s*=\s*dev)\b/i.test(line)) add(rules.find(r=>r.id==="springdebug"),n,line);
    });
    return findings;
  }
  function showResults(data) {
    const counts=data.summary.counts, findings=data.findings;
    const stat=(label,key)=>`<div class="result-stat"><b>${counts[key]||0}</b><span>${label}</span></div>`;
    const findingHtml=findings.length?findings.map(f=>`<article class="finding"><div class="finding-top"><span class="severity ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span><span class="severity">${esc(f.category)}</span></div><h4>${esc(f.title)}</h4><p class="file-line">${esc(f.file)}${f.line?":"+Number(f.line):""} · Confidence: heuristic</p><p>${esc(f.detail)}</p><p class="owner-line">Suggested owner: ${esc(f.owner)}</p><p><b>Possible next step:</b> ${esc(f.fix)}</p><p><b>Verify:</b> ${esc(f.verify)}</p></article>`).join(""):'<div class="no-findings">No supported patterns were flagged in these files. This is not a guarantee that the code is bug-free or deployable.</div>';
    results.innerHTML=`<div class="result-head"><span class="step-tag">02 / REPORT</span><h3>${esc(data.summary.readiness)}</h3><p class="result-summary">Scanned ${data.summary.files_scanned} files for <b>${esc(data.project_name)}</b>. ${data.summary.characters_scanned.toLocaleString()} characters processed locally.</p><div class="result-stats">${stat("Critical","critical")}${stat("High","high")}${stat("Medium","medium")}${stat("Low","low")}</div><p class="report-id">Report generated locally · Not saved to a server</p><h3>Findings <span style="color:#8f9bb0;font-size:12px">(${findings.length})</span></h3>${findingHtml}<div class="privacy-note"><span>ⓘ</span><p>These are heuristic pattern checks, not a full security audit. DeployBuddy does not compile or execute code, inspect dependencies, or prove deploy readiness.</p></div><button type="button" class="button secondary" id="download-report">↓ Export report JSON</button></div>`;
    results.hidden=false;
    $("#download-report").addEventListener("click",()=>{const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="deploybuddy-scan-report.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  }
  form.addEventListener("submit",e=>{
    e.preventDefault();errorBox.hidden=true;results.hidden=true;
    let outgoing=files.map(f=>({...f}));
    if(input.value.trim() && (!outgoing.length || outgoing[outgoing.length-1].content!==input.value)) outgoing.push({name:fileName.textContent||"PastedSource.java",content:input.value});
    outgoing=outgoing.filter(f=>f.content.trim());
    if(!outgoing.length){errorBox.textContent="Add at least one file or paste some code first.";errorBox.hidden=false;return;}
    if(outgoing.length>80){errorBox.textContent="Please limit your scan to 80 files.";errorBox.hidden=false;return;}
    const chars=outgoing.reduce((n,f)=>n+f.content.length,0);
    if(chars>700000){errorBox.textContent="The combined files are too large. Please scan up to 700,000 characters at a time.";errorBox.hidden=false;return;}
    scanButton.disabled=true;scanButton.querySelector("span").textContent="Analyzing…";
    try {
      const findings=outgoing.flatMap(analyzeFile);
      const counts={critical:0,high:0,medium:0,low:0};
      findings.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
      const readiness=counts.critical||counts.high?"Review high-risk findings":counts.medium?"Review before deployment":findings.length?"Review suggestions":"No supported patterns found";
      showResults({project_name:$("#project-name").value.trim()||"Untitled project",summary:{files_scanned:outgoing.length,characters_scanned:chars,counts,readiness},findings,limitations:["Browser-only rule-based analysis.","No compilation, tests, dependency scanning, or actual deployment validation."]});
      results.scrollIntoView({behavior:"smooth",block:"start"});
    } catch(err) { errorBox.textContent="The scan could not be completed. Try a smaller set of files.";errorBox.hidden=false; }
    finally {scanButton.disabled=false;scanButton.querySelector("span").textContent="Analyze project";}
  });
  renderFiles();
})();