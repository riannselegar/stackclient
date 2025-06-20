class StackSpotAgentError(Exception):
    """Base exception for StackSpot Agent client."""
    pass

class AuthenticationError(StackSpotAgentError):
    """Raised when authentication fails."""
    pass

class AgentCallError(StackSpotAgentError):
    """Raised when agent call fails."""
    pass

class MissingCredentialsError(StackSpotAgentError):
    """Raised when credentials are missing."""
    pass

class MissingAgentIDError(StackSpotAgentError):
    """Raised when agent_id is missing."""
    pass