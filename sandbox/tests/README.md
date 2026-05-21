# Sandbox 驗證指令（macOS / Docker Desktop）

先建置沙箱映像：

```bash
docker compose --profile build-only build sandbox-image
```

以下每個測試都應該在受限容器內執行，確認限制生效。

## 1) CPU 無限迴圈（TLE）

```bash
docker run --rm --network none --cpus 1 --memory 512m --pids-limit 128 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -v "$PWD/backend/temp:/work" -w /work onlineoj-sandbox:latest sh -lc 'cat > loop.c <<"C"\nint main(){for(;;){} return 0;}\nC\nclang loop.c -O2 -o loop && timeout 2s ./loop; echo exit:$?'
```

## 2) fork bomb（pids-limit）

```bash
docker run --rm --network none --cpus 1 --memory 512m --pids-limit 64 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 onlineoj-sandbox:latest sh -lc ':(){ :|:& };:; sleep 1'
```

## 3) 記憶體爆量（memory limit）

```bash
docker run --rm --network none --cpus 1 --memory 128m --pids-limit 128 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 onlineoj-sandbox:latest sh -lc 'python3 - <<"PY"\na=[]\nwhile True: a.append("x"*1024*1024)\nPY'
```

## 4) 嘗試寫系統檔（read-only）

```bash
docker run --rm --network none --cpus 1 --memory 512m --pids-limit 128 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 onlineoj-sandbox:latest sh -lc 'echo hacked >/etc/passwd'
```

## 5) 嘗試用網路（network none）

```bash
docker run --rm --network none --cpus 1 --memory 512m --pids-limit 128 --read-only --tmpfs /tmp:rw,size=64m --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 onlineoj-sandbox:latest sh -lc 'ping -c 1 8.8.8.8 || true; wget -O- https://example.com || true'
```

