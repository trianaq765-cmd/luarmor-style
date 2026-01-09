const App={
currentPage:'dashboard',
initialized:false,

async init(){
if(this.initialized)return;
console.log('[App] Initializing...');
this.bindLoginEvents();
const btn=document.getElementById('loginBtn');
if(btn){
btn.disabled=true;
btn.textContent='Checking...';
}
const isAuth=await Auth.check();
if(btn){
btn.disabled=false;
btn.textContent='🚀 Login';
}
if(isAuth){
console.log('[App] Already authenticated');
this.showDashboard();
}else{
console.log('[App] Not authenticated');
this.showLogin();
}
this.initialized=true;
},

bindLoginEvents(){
console.log('[App] Binding login events...');
const btn=document.getElementById('loginBtn');
const input=document.getElementById('adminKeyInput');
if(btn){
btn.onclick=(e)=>{
e.preventDefault();
console.log('[App] Login button clicked');
this.handleLogin();
};
console.log('[App] Login button bound');
}else{
console.error('[App] Login button not found!');
}
if(input){
input.onkeypress=(e)=>{
if(e.key==='Enter'){
e.preventDefault();
console.log('[App] Enter pressed');
this.handleLogin();
}
};
console.log('[App] Input bound');
}else{
console.error('[App] Input not found!');
}
},

async handleLogin(){
console.log('[App] handleLogin called');
const input=document.getElementById('adminKeyInput');
const btn=document.getElementById('loginBtn');
const errorEl=document.getElementById('loginError');
const errorText=document.getElementById('loginErrorText');
if(!input||!btn){
console.error('[App] Elements not found');
alert('Error: Form elements not found');
return;
}
const key=input.value;
console.log('[App] Key length:',key.length);
if(!key||key.trim().length===0){
if(errorText)errorText.textContent='Masukkan admin key';
if(errorEl)errorEl.classList.remove('hidden');
input.focus();
return;
}
if(errorEl)errorEl.classList.add('hidden');
btn.disabled=true;
btn.textContent='⏳ Verifying...';
console.log('[App] Calling Auth.login...');
try{
const result=await Auth.login(key);
console.log('[App] Login result:',result);
if(result.success){
btn.textContent='✅ Success!';
setTimeout(()=>{
this.showDashboard();
btn.textContent='🚀 Login';
btn.disabled=false;
},500);
}else{
if(errorText)errorText.textContent=result.error||'Login failed';
if(errorEl)errorEl.classList.remove('hidden');
btn.textContent='🚀 Login';
btn.disabled=false;
input.focus();
input.select();
}
}catch(err){
console.error('[App] Login error:',err);
if(errorText)errorText.textContent='Error: '+err.message;
if(errorEl)errorEl.classList.remove('hidden');
btn.textContent='🚀 Login';
btn.disabled=false;
}
},

showLogin(){
console.log('[App] Showing login');
const login=document.getElementById('loginScreen');
const dash=document.getElementById('dashboardScreen');
if(login)login.classList.remove('hidden');
if(dash)dash.classList.add('hidden');
setTimeout(()=>{
const input=document.getElementById('adminKeyInput');
if(input)input.focus();
},100);
},

showDashboard(){
console.log('[App] Showing dashboard');
const login=document.getElementById('loginScreen');
const dash=document.getElementById('dashboardScreen');
if(login)login.classList.add('hidden');
if(dash)dash.classList.remove('hidden');
this.bindNavEvents();
this.navigate('dashboard');
},

bindNavEvents(){
document.querySelectorAll('.nav-item[data-page]').forEach(item=>{
item.onclick=()=>{
const page=item.dataset.page;
if(page)this.navigate(page);
};
});
},

navigate(page){
console.log('[App] Navigate to:',page);
this.currentPage=page;
document.querySelectorAll('.nav-item').forEach(item=>{
item.classList.remove('active');
if(item.dataset.page===page)item.classList.add('active');
});
const content=document.getElementById('pageContent');
if(!content)return;
content.innerHTML='<div style="text-align:center;padding:40px"><div class="spinner"></div></div>';
setTimeout(()=>{
try{
switch(page){
case'dashboard':
content.innerHTML=Dashboard.render();
Dashboard.init();
setTimeout(()=>Dashboard.loadRecentActivity(),100);
break;
case'bans':
if(typeof Bans!=='undefined'){content.innerHTML=Bans.render();Bans.init()}
break;
case'logs':
if(typeof Logs!=='undefined'){content.innerHTML=Logs.render();Logs.init()}
break;
case'whitelist':
if(typeof Whitelist!=='undefined'){content.innerHTML=Whitelist.render();Whitelist.init()}
break;
case'sessions':
if(typeof Sessions!=='undefined'){content.innerHTML=Sessions.render();Sessions.init()}
break;
case'suspended':
if(typeof Suspended!=='undefined'){content.innerHTML=Suspended.render();Suspended.init()}
break;
case'settings':
content.innerHTML=this.renderSettings();
break;
default:
if(typeof Dashboard!=='undefined'){content.innerHTML=Dashboard.render();Dashboard.init()}
}
}catch(err){
console.error('[App] Render error:',err);
content.innerHTML='<div style="color:red;padding:20px">Error: '+err.message+'</div>';
}
},100);
},

renderSettings(){
return`<div class="page-header"><div><h1 class="page-title">Settings</h1></div></div>
<div class="card"><div class="card-header"><h3 class="card-title">🔑 Authentication</h3></div>
<div class="card-body">
<p>Admin Key: <code>${API.getKey().substring(0,4)}****</code></p>
<button class="btn btn-danger" onclick="Auth.logout()">Logout</button>
</div></div>
<div class="card" style="margin-top:20px"><div class="card-header"><h3 class="card-title">📋 Loader Script</h3></div>
<div class="card-body">
<pre style="background:#1a1a2e;padding:15px;border-radius:8px;overflow-x:auto"><code>loadstring(game:HttpGet("${window.location.origin}/loader"))()</code></pre>
<button class="btn btn-primary" style="margin-top:10px" onclick="navigator.clipboard.writeText('loadstring(game:HttpGet(&quot;${window.location.origin}/loader&quot;))()');alert('Copied!')">📋 Copy</button>
</div></div>`;
}
};

document.addEventListener('DOMContentLoaded',()=>{
console.log('[App] DOM Ready');
App.init();
});

if(document.readyState==='complete'||document.readyState==='interactive'){
console.log('[App] DOM Already Ready');
setTimeout(()=>App.init(),10);
}
