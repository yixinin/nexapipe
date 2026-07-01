# Debug Session: websocket-hanging-issue

## Status: [FIXED]

## Problem Statement
- **Symptom**: WebSocket 请求一直挂起，无法建立连接
- **Expected**: WebSocket 握手成功，双向数据流正常
- **Environment**: Windows, Rust, Iroh networking, HTTP server (8080 port), Local proxy (8081 port)
- **Reproduction**: 浏览器访问 `ws://fn.iroh.iakl.top/websocket?type=main`

## Hypotheses
| ID | Hypothesis | Status |
|----|-----------|--------|
| H1 | 后端服务器没有正确响应 WebSocket 握手 | ❌ 排除 - HTTP 正常工作 |
| H2 | local_proxy 缺少 CONNECT 隧道处理逻辑 | ✅ 确认 - 根本原因 |
| H3 | 客户端收到的握手响应不完整 | ❌ 推迟 |
| H4 | 数据转发在某个方向上阻塞 | ❌ 推迟 |
| H5 | 原始请求中的 body 数据在转发时丢失 | ❌ 推迟 |

## Evidence Log
### Pre-Fix Evidence
- local_proxy.rs 没有 CONNECT 方法处理代码
- 浏览器发送 `CONNECT fn.iroh.iakl.top:80 HTTP/1.1` 建立隧道
- CONNECT 请求被当作普通 HTTP 请求处理，导致隧道未建立

### Post-Fix Evidence
- 添加了 CONNECT 隧道支持：返回 `200 Connection Established`
- 建立双向 Iroh 流进行隧道数据转发
- WebSocket 通过隧道成功建立连接

## Root Cause Analysis

**根本原因**: `local_proxy.rs` 缺少 HTTP CONNECT 方法处理逻辑

当浏览器发起 WebSocket 连接时，它会先发送 CONNECT 请求建立隧道：
```
CONNECT fn.iroh.iakl.top:80 HTTP/1.1
Host: fn.iroh.iakl.top:80
```

正确的处理流程应该是：
1. 返回 `HTTP/1.1 200 Connection Established\r\n\r\n`
2. 建立到 Iroh 服务端的双向流
3. 在隧道内双向转发所有后续数据（包括 WebSocket Upgrade 请求）

原代码错误地将 CONNECT 请求当作普通 HTTP GET/POST 请求处理，导致隧道未建立，WebSocket 无法正常工作。

## Fix Summary

**修改文件**: `src/proxy/local_proxy.rs`

1. 添加 CONNECT 方法检测逻辑
2. 实现 `handle_connect_tunnel` 函数处理隧道双向转发
3. 返回 200 Connection Established 响应
4. 使用 tokio::io::split 分离读写流进行双向转发

## Timeline
- 2026-06-30: Session started, hypotheses defined
- 2026-06-30: Instrumentation added for debugging
- 2026-06-30: Root cause identified (missing CONNECT handling)
- 2026-06-30: Fix implemented and verified - WebSocket working