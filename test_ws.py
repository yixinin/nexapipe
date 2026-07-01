import websocket
import time

def on_message(ws, message):
    print(f"Received: {message}")

def on_error(ws, error):
    print(f"Error: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Connection closed")

def on_open(ws):
    print("WebSocket connected")
    ws.send("Hello, WebSocket!")
    time.sleep(1)
    ws.close()

if __name__ == "__main__":
    ws = websocket.WebSocketApp(
        "ws://127.0.0.1:8081/websocket?type=main",
        header={"Host": "fn.iroh.iakl.top"},
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    
    ws.run_forever()