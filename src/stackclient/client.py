import os
import json
import logging
from typing import Optional, Dict, Any
import urllib3
from .exceptions import (
    AuthenticationError,
    AgentCallError,
    MissingCredentialsError,
    MissingAgentIDError,
)

class StackSpotAgentClient:
    """
    Client for interacting with StackSpot public Agents API.
    Handles authentication and agent chat requests.
    """
    AUTH_URL = "https://idm.stackspot.com/{realm}/oidc/oauth/token"
    AGENT_API_URL = "https://genai-inference-app.stackspot.com/v1/agent/{agent_id}/chat"

    def __init__(
        self,
        realm: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        """
        Initialize the StackSpotAgentClient.

        Args:
            realm: StackSpot realm (or from STACKSPOT_REALM env var).
            client_id: OAuth client ID (or from STACKSPOT_CLIENT_ID env var).
            client_secret: OAuth client secret (or from STACKSPOT_CLIENT_SECRET env var).
            agent_id: Default agent ID (or from STACKSPOT_AGENT_ID env var).

        Raises:
            MissingCredentialsError: If any required credential is missing.
        """
        self.logger = logging.getLogger("StackSpotAgentClient")
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.client_id = client_id or os.getenv("STACKSPOT_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("STACKSPOT_CLIENT_SECRET")
        self.realm = realm or os.getenv("STACKSPOT_REALM")
        self.agent_id = agent_id or os.getenv("STACKSPOT_AGENT_ID")

        if not self.client_id or not self.client_secret or not self.realm:
            self.logger.error("The following credentials must be provided: client_id, client_secret, realm")
            raise MissingCredentialsError("Missing StackSpot client credentials.")

        self.http = urllib3.PoolManager()
        self.token = self._authenticate()

    def _authenticate(self) -> str:
        """
        Authenticate with StackSpot and obtain an access token.

        Returns:
            Access token as a string.

        Raises:
            AuthenticationError: If authentication fails.
        """
        self.logger.info("Authenticating with StackSpot...")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }
        resp = self.http.request_encode_body(
            "POST", self.AUTH_URL.format(realm=self.realm), fields=data, headers=headers, encode_multipart=False
        )
        if resp.status != 200:
            self.logger.error(f"Authentication failed: {resp.status} {resp.data.decode('utf-8')}")
            raise AuthenticationError("Authentication failed.")
        token = json.loads(resp.data.decode("utf-8"))["access_token"]
        self.logger.info("Authentication successful.")
        return token

    def call_agent(self, prompt: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a prompt to the specified StackSpot agent and return the response.

        Args:
            prompt: The user prompt to send to the agent.
            agent_id: Override the default agent ID.

        Returns:
            The agent's response as a dict.

        Raises:
            MissingAgentIDError: If agent_id is not provided.
            AgentCallError: If the agent call fails.
        """
        agent = agent_id or self.agent_id
        if not agent:
            self.logger.error("Agent ID must be provided.")
            raise MissingAgentIDError("Missing StackSpot agent_id.")

        url = self.AGENT_API_URL.format(agent_id=agent)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        payload = {
            "streaming": False,
            "user_prompt": prompt,
            "stackspot_knowledge": False,
            "return_ks_in_response": True
        }
        self.logger.info(f"Calling agent endpoint: {url}")
        resp = self.http.request(
            "POST", url, json=payload, headers=headers
        )
        self.logger.info(f"Response status: {resp.status}")
        if resp.status != 200:
            self.logger.error(f"Agent call failed: {resp.status} {resp.data.decode('utf-8')}")
            raise AgentCallError("Agent call failed.")
        return json.loads(resp.data.decode("utf-8"))