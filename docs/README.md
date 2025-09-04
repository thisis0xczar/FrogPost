# FrogPost: postMessage Security Testing Tool

FrogPost is a Chrome extension for comprehensive security testing of `postMessage` communications between iframes. It combines static analysis, dynamic testing, and optional AI assistance to identify vulnerabilities in message-handling implementations.

#### Current Version: FrogPost v2.0.0

<p align="center" width="100%">
    <img width="15%" src="media/frog-logo.png">
</p>

## Preview
<p align="center" width="100%">
    <img width="80%" src="media/FrogPost_final.gif">
</p>

---

## ⚠️ Security Disclaimer

Use FrogPost **ethically and legally** — only test applications you own or have permission to assess. Unauthorized testing may violate laws.

---

## 🚀 Key Features

### AI Assistance (Optional)
- Integration with providers like OpenAI, Anthropic, Groq, and Mistral
- AI-suggested payloads tailored to detected handlers
- Optional handler validation / risk notes



### 🎯 **Core Capabilities**
- Live monitoring of cross-origin `postMessage` traffic
- Automatic detection and analysis of message handlers
- Static and runtime analysis for DOM-based vulnerabilities
- Identification of missing origin checks and unsafe sinks
- Advanced payload fuzzing with envelope-aware generation
- Real-time server status monitoring and management

---

## 📌 Usage Workflow

### 🎯 **Basic Analysis (No Server Required)**
1. **Observe**: Load any site with iframes. FrogPost automatically captures `postMessage` exchanges
2. **Analyze**: Click ▶ to begin handler detection. Static analysis provides comprehensive coverage
3. **Generate**: Use "Generate & Merge Smart Payloads" for basic payload generation
4. **Test**: Launch 🚀 to test endpoints with crafted payloads

### 🧠 **AI-Enhanced Analysis (Server Required)**
1. **Setup**: Run `bash setup.sh` once to install the local server
2. **Configure**: Add your LLM API keys in the Options page  
3. **Start Server**: Use `bash setup.sh start` or `npm run server:bg`
4. **Enhanced Analysis**: Click "Analyze with LLM" for AI-powered insights
5. **Smart Testing**: Get AI-generated payloads tailored to detected handlers

---

## 🎛️ Dashboard Interface

### 🖥️ **Server Status Bar**
- **Green Indicator**: ✅ Server running - AI features available
- **Red Indicator**: ❌ Server stopped - Basic features only
- **Auto-monitoring**: Real-time server status updates

### Per-Endpoint Controls
- Analyze Handler – Detect and analyze message handlers
- Analyze with LLM – Optional AI analysis (requires server)
- Generate & Merge Smart Payloads – Create test payloads
- Show Report – View detailed findings
- Launch Fuzzer – Execute payload-based security testing

### Global Controls
- Check All Endpoints – Batch analysis of all detected handlers
- Clear Messages – Reset captured message state  
- Export Data – Download messages and analysis results
- Refresh – Manually update message capture
- Debug Mode – Enable verbose console logging

### 📊 **Analysis Panels**
- **Messages Panel** – Real-time `postMessage` traffic monitoring
- **Handler Analysis** – Static and dynamic handler detection results
- **LLM Insights** – AI-powered security assessment and recommendations
- **Smart Payloads** – Generated test cases with risk ratings
- **Fuzzing Results** – Live testing feedback and vulnerability reports

---

## 🚀 Quick Installation Guide

### 📋 **Prerequisites**
- Google Chrome browser
- Node.js and npm installed ([Download here](https://nodejs.org/))
- macOS, Windows, or Linux

---

### 🎯 **One-Command Installation (Recommended)**

1. **Clone the repository:**
    ```bash
    git clone https://github.com/thisis0xczar/FrogPost.git
    cd FrogPost
    ```

2. **Run the automated installer:**
    ```bash
    bash setup.sh
    ```
    
    The setup script will:
    - ✅ Install native messaging host for Chrome extension communication  
    - ✅ Set up the local server with all dependencies
    - ✅ Configure server management through `setup.sh`
    - ✅ Optionally start the server immediately

3. **Load the Chrome extension:**
    - Go to `chrome://extensions/` in Chrome
    - Enable **Developer mode** (top-right toggle)
    - Click **Load unpacked** and select the FrogPost folder
    - Extension will appear in your extensions list

4. **Configure LLM features (optional but recommended):**
    - Click the FrogPost extension icon → Options
    - Add your API keys for OpenAI, Anthropic, Groq, or Mistral
    - Save settings

---

### 🖥️ **Server Management**

After installation, manage the FrogPost server easily:

```bash
# Start server in background
bash setup.sh start
# or: npm run server:bg

# Check server status  
bash setup.sh status
# or: npm run server:status

# Stop server
bash setup.sh stop  
# or: npm run server:stop

# Restart server
bash setup.sh restart
# or: npm run server:restart
```

**The Chrome extension works without the server (basic features), but AI analysis requires the server to be running.**

---

### 🔧 **Manual Installation (Alternative)**

If you prefer manual setup:

1. **Clone and load extension** (steps 1 & 3 from above)

2. **Manual server setup:**
    ```bash
    cd server/
    npm install express cors body-parser
    node server.js  # Runs in foreground
    ```

---

## 🪟 Windows Installation

### **Windows Setup Process:**

1. **Clone the repository:**
    ```powershell
    git clone https://github.com/thisis0xczar/FrogPost.git
    cd FrogPost
    ```

2. **Use Windows-specific installer:**
    ```powershell
    powershell.exe -ExecutionPolicy Bypass -File Windows/setup.ps1
    ```

3. **Load Chrome extension** (same as macOS steps 3-4 above)

---

## 🔧 Configuration & Customization

### 🤖 **LLM Provider Setup**

FrogPost supports multiple AI providers for enhanced analysis:

| Provider | Models Available | Setup |
|----------|------------------|-------|
| **OpenAI** | gpt-4o, gpt-4o-mini, gpt-4-turbo | Add OpenAI API key in Options |
| **Anthropic** | claude-3-sonnet, claude-3-haiku | Add Anthropic API key in Options |  
| **Groq** | llama-3.1, mixtral-8x7b | Add Groq API key in Options |
| **Mistral** | mistral-large, mistral-small | Add Mistral API key in Options |

### 🔒 **Security Features**

- **JWT Protection**: Real JWTs are automatically replaced with dummy tokens in:
  - Generated payloads sent to target applications
  - Data sent to LLM providers for analysis
- **Local Processing**: Sensitive analysis happens locally before sanitization
- **API Key Security**: Keys stored securely in Chrome extension storage

---

## 🧪 Troubleshooting

### **Common Issues & Solutions**

| Issue | Solution |
|-------|----------|
| **❌ Server Status: Stopped** | Run `bash setup.sh start` or `npm run server:bg` |
| **🔌 Could not connect to server** | Check if Node.js is installed and port 1337 is available |
| **🔑 LLM features not working** | Ensure server is running and API keys are configured in Options |
| **📱 Extension not loading** | Enable Developer Mode in `chrome://extensions/` |
| **⚠️ Permission denied** | Run `chmod +x setup.sh` on macOS/Linux |
| **🚫 Node.js not found** | Install Node.js from [nodejs.org](https://nodejs.org/) |

### **Debug Mode**
Enable verbose logging for troubleshooting:
1. Open FrogPost dashboard
2. Toggle "Debug Mode" in global controls
3. Check browser console for detailed logs

---

## 🚀 What's New in v2.0.0

### 🧠 **AI Integration**
- [x] LLM-powered security analysis with multiple provider support
- [x] AI-generated payloads tailored to detected handlers
- [x] Intelligent handler quality scoring
- [x] Comprehensive risk assessment with explanations

### 🔒 **Security Enhancements** 
- [x] JWT sanitization for all generated payloads and LLM inputs
- [x] Privacy-first approach - no real sensitive data sent to external APIs
- [x] Enhanced envelope detection for better payload generation

### ⚙️ **Server Automation**
- [x] One-command installation via `setup.sh`
- [x] Background server management
- [x] Real-time server status monitoring in extension
- [x] Automatic server health checks

### 🎯 **Improved Analysis**
- [x] Smart payload generation with envelope awareness
- [x] Enhanced AST parsing with better error handling  
- [x] Improved handler detection heuristics
- [x] Better static analysis fallbacks

---

## 📅 Development Roadmap

### **Completed ✅**
- [x] AI-powered security analysis
- [x] Multi-LLM provider support  
- [x] JWT sanitization system
- [x] Automated server management
- [x] Enhanced payload generation
- [x] Real-time server monitoring

### **In Progress 🚧**
- [ ] Advanced AST parsing for complex listener patterns
- [ ] Machine learning-based vulnerability classification
- [ ] Browser extension for Firefox support

### **Planned 🎯**
- [ ] Integration with popular security testing frameworks
- [ ] Automated report generation and export
- [ ] Advanced fuzzing techniques with ML-driven mutations

---

## 📄 License

FrogPost is licensed under the MIT License. See [LICENSE](LICENSE) for full details.

### **Third-party Components**

- **Acorn** (MIT License) - JavaScript parser
- **acorn-walk** (MIT License) - AST walker  
- **Express.js** (MIT License) - Web server framework
- **CORS** (MIT License) - Cross-Origin Resource Sharing

> © Marijn Haverbeke and contributors (Acorn), © OpenJS Foundation and contributors (Express.js)

See [`third_party_licenses.md`](third_party_licenses.md) for complete license texts.

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Test** your changes thoroughly
4. **Commit** your changes (`git commit -m 'Add amazing feature'`)
5. **Push** to the branch (`git push origin feature/amazing-feature`)
6. **Open** a Pull Request

### **Development Setup**
```bash
git clone https://github.com/your-username/FrogPost.git
cd FrogPost
bash setup.sh      # Install dependencies
npm run dev        # Start development server
```

---

## 📬 Support & Community  

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/thisis0xczar/FrogPost/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/thisis0xczar/FrogPost/discussions)  
- **🔒 Security Issues**: Please email security@frogpost.dev (private disclosure)
- **📖 Documentation**: [GitHub Wiki](https://github.com/thisis0xczar/FrogPost/wiki)

---

<p align="center">
    <b>🐸 Happy Security Testing with FrogPost! 🐸</b><br/>
    <i>Advanced postMessage Security Testing Tool</i>
</p>

---

**Made with ❤️ by [thisis0xczar](https://github.com/thisis0xczar) and the security community**
