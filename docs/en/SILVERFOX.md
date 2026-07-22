# 🦊 SilverFox Malware Analysis Guide

> [中文](../SILVERFOX.md)

> Applies to Spore 4.0. Launch from desktop or CLI and follow the instructions below to reproduce; samples and outputs are in `example/MalwareAnalysis/SliverFox/`.

## 📋 Preparation

### 1. Install the Software

Download the installer from the [Release page](https://github.com/miunasu/Spore/releases) and complete the installation.

### 2. Prepare the Analysis Materials

Prepare the [sample files](../../example/MalwareAnalysis/SliverFox/SliverFox1/malware/) needed to analyze SilverFox.

### 3. Configure the LLM

Fill in the following configuration in the `.env` file in the installation directory (see the [configuration documentation](CONFIGURATION.md) for variable descriptions):

```env
# Using an OpenAI-compatible API as an example
LLM_SDK=openai
OPENAI_API_KEY=your_api_key_here
OPENAI_API_URL=your_api_url_here
OPENAI_MODEL=your_model_name

# Token limits (adjust according to the model you use)
MAX_OUTPUT_TOKENS=8000        # Maximum number of tokens per LLM output
CONTEXT_MAX_TOKENS=128000     # Maximum number of context tokens
```

For the Anthropic API, use `LLM_SDK=anthropic` + `ANTHROPIC_API_KEY` / `ANTHROPIC_API_URL` / `ANTHROPIC_MODEL` instead.

### 4. Configure IDA-Skill

Download the [latest IDA-Skill](https://github.com/miunasu/IDA-Skill) and place it in the `skills/` folder of the installation directory.

Edit `skills/IDA-Skill/config.json` and fill in the absolute path of `idat.exe` in your IDA directory.

Example:
```json
{
  "ida_path": "C:\\Program Files\\IDA Pro\\idat.exe"
}
```

---

## 🚀 Starting the Analysis

### Launch Spore

Double-click `Spore.exe` to start the program.

### Send the Analysis Instruction

Send Spore the following analysis instruction (adjust for your actual paths):

```
I have prepared samples for you at path\to\malware. Please analyze them.

The sample directory contains the following files:
- Main sample i64 file: libexpat.dll.i64 (processed with REAI)
- The sample itself: libexpat.dll
- Persistence record folder: persistence_report_b0c27ebf2b0814f7150864d505a8f478_byovd_drv_20260202_200131
- Malware configuration file: box.ini
- Follow-up communication content: the data subfolder
```

During the analysis, you can watch progress via the log panel on the left and the Agent monitor and TODO bar on the right; reports are produced in the `output/` directory by default.

---

## 📝 Notes

- Make sure the sample file paths are correct and accessible
- **Do not run the sample itself**: the analysis is based on static reverse engineering and existing record files; the security agent (`SECURITY_AGENT_MODE=full`, the default) will circuit-break suspicious execution commands
- The analysis may take a long time, so please be patient
- If both `idat.exe` and `idat64.exe` exist in the IDA directory, fill in `idat.exe`, because this sample is 32-bit
- It is recommended to use the character `characters/Malware analyst.md` (via `char select` or in the desktop settings)
