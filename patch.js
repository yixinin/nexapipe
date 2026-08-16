var fs = require('fs');
var NL = String.fromCharCode(13,10);
var src = fs.readFileSync('crates/nexapipe/src/conn/mod.rs.bak','utf16le').replace(/^\uFEFF/,'');
var c = src;
c = c.replace('use crate::http;','use crate::auth::{AuthConfig, AuthMessage, TotpValidator};' + NL + 'use crate::http;');
var oldSig = 'pub async fn handle_connection(' + NL + '    conn: Connection,' + NL + '    config: Arc<RouteConfig>,' + NL + '    client: Arc<HttpClient>,' + NL + ')';
var newSig = 'pub async fn handle_connection(' + NL + '    conn: Connection,' + NL + '    config: Arc<RouteConfig>,' + NL + '    client: Arc<HttpClient>,' + NL + '    auth_config: Option<Arc<tokio::sync::RwLock<AuthConfig>>>,' + NL + ')';
c = c.replace(oldSig, newSig);
