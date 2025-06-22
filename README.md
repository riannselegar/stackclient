# stackclient

[![PyPI version](https://badge.fury.io/py/stackclient.svg)](https://pypi.org/project/stackclient/)

A simple Python client for interacting with [StackSpot](https://stackspot.com/) public Agents API.  
Handles authentication (OAuth2 client credentials) and allows you to send prompts to StackSpot agents.

---

## Features

- Authenticate with StackSpot using OAuth2 client credentials.
- Send prompts to any StackSpot agent and receive responses.
- Minimal dependencies (`urllib3`).

---

## Installation

Install from PyPI:

```bash
pip install stackclient
```

---

## Usage

### 1. Import and Initialize

You can provide credentials directly or via environment variables:

- `STACKSPOT_CLIENT_ID`
- `STACKSPOT_CLIENT_SECRET`
- `STACKSPOT_REALM`
- `STACKSPOT_AGENT_ID` (optional, can be set per call)

```python
from stackclient.client import StackSpotAgentClient

# Option 1: Pass credentials directly
client = StackSpotAgentClient(
    realm="your-realm",
    client_id="your-client-id",
    client_secret="your-client-secret",
    agent_id="your-agent-id"  # optional, can be set per call
)

# Option 2: Use environment variables
# export STACKSPOT_CLIENT_ID=your-client-id
# export STACKSPOT_CLIENT_SECRET=your-client-secret
# export STACKSPOT_REALM=your-realm
# export STACKSPOT_AGENT_ID=your-agent-id
client = StackSpotAgentClient()
```

### 2. Call an Agent

```python
try:
    response = client.call_agent("Hello, StackSpot agent!")
    print(response)
except Exception as e:
    print(f"Error: {e}")
```

You can override the default agent ID per call:

```python
response = client.call_agent("Prompt for another agent", agent_id="another-agent-id")
```

---

## Exception Handling

- `AuthenticationError`: Raised if authentication fails.
- `AgentCallError`: Raised if the agent call fails.
- `MissingCredentialsError`: Raised if required credentials are missing.
- `MissingAgentIDError`: Raised if no agent ID is provided.

---

## Requirements

- Python 3.7+
- `urllib3>=2.5.0`

---

## License

MIT

---

## Example

```python
from stackclient.client import StackSpotAgentClient

client = StackSpotAgentClient(
    realm="myrealm",
    client_id="myclientid",
    client_secret="mysecret",
    agent_id="myagentid"
)
result = client.call_agent("What is StackSpot?")
print(result)
```