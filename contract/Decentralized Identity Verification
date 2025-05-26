// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IdentityVerification
 * @dev Smart contract for decentralized identity verification system
 * @author Identity Verification Team
 */
contract IdentityVerification {
    
    // Structure to store identity information
    struct Identity {
        string name;
        string documentHash; // IPFS hash of encrypted identity documents
        uint256 verificationLevel; // 0: Unverified, 1: Basic, 2: Enhanced, 3: Premium
        uint256 timestamp;
        bool isActive;
        address verifier; // Address of the entity that verified this identity
    }
    
    // Structure for verification requests
    struct VerificationRequest {
        address requester;
        string documentHash;
        uint256 requestTimestamp;
        bool isPending;
        string notes;
    }
    
    // Mapping from user address to their identity
    mapping(address => Identity) public identities;
    
    // Mapping from user address to verification requests
    mapping(address => VerificationRequest[]) public verificationRequests;
    
    // Mapping of authorized verifiers
    mapping(address => bool) public authorizedVerifiers;
    
    // Contract owner
    address public owner;
    
    // Events
    event IdentityRegistered(address indexed user, string name, uint256 timestamp);
    event IdentityVerified(address indexed user, uint256 verificationLevel, address indexed verifier);
    event VerificationRequested(address indexed user, string documentHash, uint256 timestamp);
    event VerifierAuthorized(address indexed verifier, address indexed authorizer);
    event VerifierRevoked(address indexed verifier, address indexed revoker);
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can call this function");
        _;
    }
    
    modifier onlyAuthorizedVerifier() {
        require(authorizedVerifiers[msg.sender], "Only authorized verifiers can call this function");
        _;
    }
    
    modifier identityExists(address _user) {
        require(identities[_user].timestamp > 0, "Identity does not exist");
        _;
    }
    
    /**
     * @dev Constructor sets the contract deployer as owner
     */
    constructor() {
        owner = msg.sender;
        authorizedVerifiers[msg.sender] = true; // Owner is automatically an authorized verifier
    }
    
    /**
     * @dev Core Function 1: Register a new identity
     * @param _name Full name of the user
     * @param _documentHash IPFS hash of encrypted identity documents
     */
    function registerIdentity(string memory _name, string memory _documentHash) external {
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_documentHash).length > 0, "Document hash cannot be empty");
        require(identities[msg.sender].timestamp == 0, "Identity already registered");
        
        identities[msg.sender] = Identity({
            name: _name,
            documentHash: _documentHash,
            verificationLevel: 0, // Unverified initially
            timestamp: block.timestamp,
            isActive: true,
            verifier: address(0)
        });
        
        emit IdentityRegistered(msg.sender, _name, block.timestamp);
    }
    
    /**
     * @dev Core Function 2: Verify an identity (only authorized verifiers)
     * @param _user Address of the user to verify
     * @param _verificationLevel Level of verification (1-3)
     */
    function verifyIdentity(address _user, uint256 _verificationLevel) external 
        onlyAuthorizedVerifier 
        identityExists(_user) 
    {
        require(_verificationLevel >= 1 && _verificationLevel <= 3, "Invalid verification level");
        require(identities[_user].isActive, "Identity is not active");
        
        identities[_user].verificationLevel = _verificationLevel;
        identities[_user].verifier = msg.sender;
        
        emit IdentityVerified(_user, _verificationLevel, msg.sender);
    }
    
    /**
     * @dev Core Function 3: Request identity verification
     * @param _documentHash Updated document hash for verification
     * @param _notes Additional notes for the verification request
     */
    function requestVerification(string memory _documentHash, string memory _notes) external 
        identityExists(msg.sender) 
    {
        require(identities[msg.sender].isActive, "Identity is not active");
        require(bytes(_documentHash).length > 0, "Document hash cannot be empty");
        
        verificationRequests[msg.sender].push(VerificationRequest({
            requester: msg.sender,
            documentHash: _documentHash,
            requestTimestamp: block.timestamp,
            isPending: true,
            notes: _notes
        }));
        
        emit VerificationRequested(msg.sender, _documentHash, block.timestamp);
    }
    
    /**
     * @dev Get identity information for a user
     * @param _user Address of the user
     * @return Identity struct containing user's identity information
     */
    function getIdentity(address _user) external view returns (Identity memory) {
        require(identities[_user].timestamp > 0, "Identity does not exist");
        return identities[_user];
    }
    
    /**
     * @dev Get verification level of a user
     * @param _user Address of the user
     * @return Verification level (0-3)
     */
    function getVerificationLevel(address _user) external view returns (uint256) {
        return identities[_user].verificationLevel;
    }
    
    /**
     * @dev Check if an address has a verified identity
     * @param _user Address to check
     * @return True if verified (level > 0), false otherwise
     */
    function isVerified(address _user) external view returns (bool) {
        return identities[_user].verificationLevel > 0 && identities[_user].isActive;
    }
    
    /**
     * @dev Get verification requests for a user
     * @param _user Address of the user
     * @return Array of verification requests
     */
    function getVerificationRequests(address _user) external view returns (VerificationRequest[] memory) {
        return verificationRequests[_user];
    }
    
    /**
     * @dev Authorize a new verifier (only owner)
     * @param _verifier Address to authorize as verifier
     */
    function authorizeVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        require(!authorizedVerifiers[_verifier], "Verifier already authorized");
        
        authorizedVerifiers[_verifier] = true;
        emit VerifierAuthorized(_verifier, msg.sender);
    }
    
    /**
     * @dev Revoke verifier authorization (only owner)
     * @param _verifier Address to revoke authorization from
     */
    function revokeVerifier(address _verifier) external onlyOwner {
        require(authorizedVerifiers[_verifier], "Verifier not authorized");
        require(_verifier != owner, "Cannot revoke owner's verification rights");
        
        authorizedVerifiers[_verifier] = false;
        emit VerifierRevoked(_verifier, msg.sender);
    }
    
    /**
     * @dev Deactivate user's identity (only owner or user themselves)
     * @param _user Address of the user to deactivate
     */
    function deactivateIdentity(address _user) external identityExists(_user) {
        require(msg.sender == owner || msg.sender == _user, "Unauthorized to deactivate this identity");
        
        identities[_user].isActive = false;
    }
    
    /**
     * @dev Update identity document hash (only by identity owner)
     * @param _newDocumentHash New IPFS hash of updated documents
     */
    function updateDocumentHash(string memory _newDocumentHash) external identityExists(msg.sender) {
        require(bytes(_newDocumentHash).length > 0, "Document hash cannot be empty");
        require(identities[msg.sender].isActive, "Identity is not active");
        
        identities[msg.sender].documentHash = _newDocumentHash;
        // Reset verification level when documents are updated
        identities[msg.sender].verificationLevel = 0;
        identities[msg.sender].verifier = address(0);
    }
}
