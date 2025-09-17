# FrogPost: postMessage Security Testing Tool

FrogPost is a Chrome extension for security testing of `postMessage` communications between iframes. It combines static analysis, dynamic testing, and optional AI assistance to identify vulnerabilities in message-handling implementations.

#### Current Version: FrogPost v2.0.1

<p align="center" width="100%">
    <img width="15%" src="media/frog-logo.png">
</p>

## Preview
<p align="center" width="100%">
    <img width="80%" src="media/FrogPost_final.gif">
</p>

---

## ⚠️ Security Disclaimer

Use FrogPost **ethically and legally** — only test applications you own or have permission to assess.

---

## 🚀 Quick Start

### **Step 1: Load Extension**
1. Go to `chrome://extensions/` in Chrome
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the FrogPost folder
4. Copy the Extension ID from the extensions page

### **Step 2: Setup Server**
```bash
bash setup.sh
```
*This installs dependencies and sets up the local server for AI features*

### **Step 3: Start Using**
1. Visit any website with iframes
2. Click the FrogPost extension icon
3. Click **Analyze Handler** to detect vulnerabilities
4. Click **Launch Fuzzer** to test with payloads

### **Step 4: Enable AI Features (Optional)**
1. Click extension icon → **Options**
2. Add your API key (OpenAI, Anthropic, Groq, or Mistral)
3. Start server: `bash setup.sh start`
4. Use **"Analyze with LLM"** for AI-powered insights

---

## 🎯 Core Features

- **Live Monitoring**: Captures `postMessage` traffic between iframes
- **Handler Analysis**: Detects and analyzes message handlers for vulnerabilities
- **Payload Testing**: Launches crafted payloads to test security
- **AI Enhancement**: Optional LLM-powered analysis (requires server)

### **What FrogPost Detects**
- Missing origin validation in message handlers
- Unsafe DOM sinks (innerHTML, eval, etc.)
- Prototype pollution vulnerabilities
- XSS injection points in postMessage handlers
- Security misconfigurations in iframe communication

---

## 🖥️ Server Management

```bash
# Start server
bash setup.sh start

# Check status
bash setup.sh status

# Stop server
bash setup.sh stop
```

**Note**: Basic features work without the server, but AI analysis requires it to be running.

---

## 🤖 AI Features (Optional)

### **Supported Providers**
| Provider | Models | Cost |
|----------|--------|------|
| **OpenAI** | gpt-4o, gpt-4o-mini | ~$0.01-0.03 per analysis |
| **Anthropic** | claude-3-sonnet, claude-3-haiku | ~$0.01-0.02 per analysis |
| **Groq** | llama-3.1, mixtral-8x7b | ~$0.001-0.005 per analysis |
| **Mistral** | mistral-large, mistral-small | ~$0.005-0.015 per analysis |

### **Setup AI Features**
1. **Configure API Keys**: Click extension icon → Options
2. **Add your keys**: Choose any supported provider above
3. **Start server**: `bash setup.sh start`
4. **Use AI analysis**: Click "Analyze with LLM" in the dashboard

### **What AI Analysis Provides**
- **Handler Quality Score**: 0-100 accuracy rating
- **Security Assessment**: Detailed vulnerability analysis
- **Custom Payloads**: AI-generated payloads for detected sinks
- **Risk Recommendations**: Specific security improvements

---

## 🧪 Troubleshooting

| Issue | Solution |
|-------|----------|
| **❌ Server not running** | Run `bash setup.sh start` |
| **🔌 Connection failed** | Check if Node.js is installed |
| **📱 Extension not loading** | Enable Developer Mode in Chrome |
| **⚠️ Permission denied** | Run `chmod +x setup.sh` |
| **🤖 AI features not working** | Ensure server is running and API keys are configured |
| **🔑 API key errors** | Check key validity and provider selection |

### **Common Solutions**
- **Server won't start**: Check if port 1337 is available
- **Extension crashes**: Refresh the page and try again
- **No messages captured**: Ensure the site has iframe communication
- **Analysis fails**: Check browser console for error details

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🔗 Useful Links

- **GitHub Repository**: [github.com/thisis0xczar/FrogPost](https://github.com/thisis0xczar/FrogPost)
- **Bug Reports**: [GitHub Issues](https://github.com/thisis0xczar/FrogPost/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/thisis0xczar/FrogPost/discussions)

---

<p align="center">
    <b>🐸 Happy Security Testing! 🐸</b>
</p>

**Made with ❤️ by [thisis0xczar](https://github.com/thisis0xczar)**
