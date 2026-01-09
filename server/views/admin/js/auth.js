const Auth={
isAuthenticated:false,

async check(){
console.log('[Auth] Checking session...');
const key=API.getKey();
if(!key){
console.log('[Auth] No saved key');
this.isAuthenticated=false;
return false;
}
console.log('[Auth] Found saved key, verifying...');
const result=await API.get('/api/admin/stats');
this.isAuthenticated=result.success===true;
console.log('[Auth] Verified:',this.isAuthenticated);
if(!this.isAuthenticated){
API.clearKey();
}
return this.isAuthenticated;
},

async login(adminKey){
console.log('[Auth] Login attempt...');
if(!adminKey||adminKey.trim().length<5){
return{success:false,error:'Key terlalu pendek (min 5 karakter)'};
}
const trimmedKey=adminKey.trim();
API.setKey(trimmedKey);
console.log('[Auth] Key set, verifying with server...');
const result=await API.get('/api/admin/stats');
console.log('[Auth] Server response:',result);
if(result.success){
this.isAuthenticated=true;
return{success:true};
}else{
API.clearKey();
this.isAuthenticated=false;
return{success:false,error:result.error||'Invalid key'};
}
},

logout(){
console.log('[Auth] Logging out');
API.clearKey();
this.isAuthenticated=false;
if(typeof App!=='undefined')App.showLogin();
}
};
