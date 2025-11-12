import { Contract, ethers, AbiCoder } from 'ethers';
import { BundlerService, UserOperation } from './BundlerService';
import crypto from 'crypto';
import { FactoryABI } from '../abis/FactoryAbi';
import { EntryPointABI } from '../abis/EntryPointABI';

export class AAService {
    private provider: ethers.JsonRpcProvider;
    private bundler: BundlerService;
    private factoryAddress: string;
    private entryPointAddress: string;
    private paymasterAddress: string;
    private paymasterSigner: ethers.Wallet;
    private chainId: number | undefined;

    constructor() {
        this.provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
        this.bundler = new BundlerService();
        this.factoryAddress = process.env.FACTORY_ADDRESS!;
        this.entryPointAddress = process.env.ENTRYPOINT_ADDRESS!;
        this.paymasterAddress = process.env.PAYMASTER_ADDRESS!;
        this.paymasterSigner = new ethers.Wallet(
            process.env.PAYMASTER_SIGNER_PRIVATE_KEY!,
            this.provider
        );
    }

    async init() {
        this.chainId = Number((await this.provider.getNetwork()).chainId);
        console.log('AA Service initialized');
        console.log('Chain ID:', this.chainId);
        console.log('EntryPoint:', this.entryPointAddress);
        console.log('Factory:', this.factoryAddress);
        console.log('Paymaster:', this.paymasterAddress);
    }

    /**
     * IMPORTANT: This creates the smart account address
     * But the DEVICE generates and holds the private key!
     * Backend only stores encrypted recovery data
     */
    async createSmartAccount(userId: string, ownerWalletAddress: string, salt: number = 0, decryptingKey: string): Promise<{
        smartAccountAddress: string;
        encryptedRecoveryData: string;
    }> {
        // Calculate counterfactual address
        const factory = new Contract(
            this.factoryAddress,
            FactoryABI,
            this.provider
        );

        const smartAccountAddress = await (factory as any).getAddress(ownerWalletAddress, ethers.toBigInt(salt));

        // Create recovery data (encrypted wallet address + salt)
        const recoveryData = JSON.stringify({
            smartAccountAddress,
            decryptingKey,
            salt: salt.toString(),
            createdAt: Date.now()
        });

        const encryptedRecoveryData = this.encryptRecoveryData(recoveryData, userId);

        console.log('✅ Smart account created (counterfactual)');
        console.log('   Address:', smartAccountAddress);
        console.log('   Owner (device):', decryptingKey);

        return {
            smartAccountAddress,
            encryptedRecoveryData
        };
    }

    /**
     * Build UserOperation for token transfer
     * Device will sign this UserOp
     */
    async buildTokenTransferUserOp(
        smartAccountAddress: string,
        toAddress: string,
        amount: string,
        isDeployed: boolean
    ): Promise<Partial<UserOperation>> {
        console.log('Building UserOp...');

        // 1. Encode token transfer
        const tokenInterface = new ethers.Interface([
            'function transfer(address,uint256) returns (bool)'
        ]);
        const transferData = tokenInterface.encodeFunctionData('transfer', [
            toAddress,
            ethers.parseUnits(amount, 18)
        ]);

        // 2. Encode account.execute()
        const accountInterface = new ethers.Interface([
            'function execute(address,uint256,bytes)'
        ]);
        const callData = accountInterface.encodeFunctionData('execute', [
            process.env.UMC_TOKEN_ADDRESS!,
            0,
            transferData
        ]);

        // 3. Get initCode if not deployed
        let initCode = '0x';
        if (!isDeployed) {
            // Will be filled by frontend with factory.createAccount()
            console.log('   Account not deployed, will deploy on first tx');
        }

        // 4. Get nonce
        const entryPoint = new Contract(
            this.entryPointAddress,
            EntryPointABI,
            this.provider
        );
        const nonce = await entryPoint.getNonce(smartAccountAddress, 0);

        // 5. Get gas prices
        const gasFees = await this.bundler.getGasFees();

        // 6. Build partial UserOp (device will complete and sign)
        const partialUserOp: Partial<UserOperation> = {
            sender: smartAccountAddress,
            nonce: nonce.toHexString(),
            initCode,
            callData,
            callGasLimit: ethers.toBeHex(isDeployed ? 100000 : 200000),
            verificationGasLimit: ethers.toBeHex(isDeployed ? 300000 : 700000),
            preVerificationGas: ethers.toBeHex(50000),
            maxFeePerGas: gasFees.maxFeePerGas,
            maxPriorityFeePerGas: gasFees.maxPriorityFeePerGas,
            paymasterAndData: '0x', // Will add paymaster signature
            signature: '0x' // Device will sign
        };

        console.log('   UserOp built successfully');
        return partialUserOp;
    }

    /**
     * Add paymaster signature to sponsor gas
     * This is what backend does - sponsors the transaction!
     */
    async addPaymasterSignature(userOp: UserOperation): Promise<string> {
        console.log('🔏 Adding paymaster signature...');

        const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 minutes
        const validAfter = 0;

        // Create hash to sign
        const abiCoder = AbiCoder.defaultAbiCoder();
        const hash = ethers.keccak256(
            abiCoder.encode(
                ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'address', 'uint48', 'uint48'],
                [
                    userOp.sender,
                    userOp.nonce,
                    userOp.callGasLimit,
                    userOp.verificationGasLimit,
                    userOp.preVerificationGas,
                    userOp.maxFeePerGas,
                    userOp.maxPriorityFeePerGas,
                    this.chainId,
                    this.paymasterAddress,
                    validUntil,
                    validAfter
                ]
            )
        );

        // Sign with paymaster signer
        const signature = await this.paymasterSigner.signMessage(
            ethers.getBytes(hash)
        );
        // Pack paymasterAndData
        const paymasterAndData = ethers.concat([
            this.paymasterAddress,
            abiCoder.encode(['uint48', 'uint48'], [validUntil, validAfter]),
            signature
        ]);

        console.log('   ✅ Gas sponsored!');
        return paymasterAndData;
    }

    async addPaymasterSignature_v0_7(userOp: UserOperation): Promise<string> {
        console.log('🔏 Adding paymaster signature (v0.7 format)...');

        const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 mins
        const validAfter = 0;

        // 1. Compute userOpHash using EntryPoint contract
        const entryPoint = new Contract(this.entryPointAddress, EntryPointABI, this.provider);
        const userOpHash = await entryPoint.getUserOpHash(userOp);

        // 2. Compute paymaster hash according to ERC-4337 v0.7
        const abiCoder = ethers.AbiCoder.defaultAbiCoder();
        const paymasterHash = ethers.keccak256(
            abiCoder.encode(
                ['bytes32', 'uint48', 'uint48', 'address'],
                [userOpHash, validUntil, validAfter, this.paymasterAddress]
            )
        );

        // 3. Sign it with your paymaster private key
        const signature = await this.paymasterSigner.signMessage(ethers.getBytes(paymasterHash));

        // 4. Pack paymasterAndData (address + validity + signature)
        const paymasterAndData = ethers.concat([
            this.paymasterAddress,
            abiCoder.encode(['uint48', 'uint48'], [validUntil, validAfter]),
            signature
        ]);

        console.log('✅ Real paymaster signature added');
        return paymasterAndData;
    }

    /**
     * Submit UserOperation to bundler
     */
    async submitUserOperation(userOp: UserOperation): Promise<string> {
        return await this.bundler.sendUserOperation(userOp);
    }

    /**
     * Wait for transaction confirmation
     */
    async waitForConfirmation(userOpHash: string): Promise<any> {
        return await this.bundler.waitForUserOperationReceipt(userOpHash);
    }

    // Recovery helpers
    private encryptRecoveryData(data: string, userId: string): string {
        // const key = crypto.scryptSync(process.env.RECOVERY_ENCRYPTION_KEY!, userId, 32);
        // const iv = crypto.randomBytes(16);
        // const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

        // let encrypted = cipher.update(data, 'utf8', 'hex');
        // encrypted += cipher.final('hex');

        // const authTag = cipher.getAuthTag();

        // return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;


        const masterKey = process.env.RECOVERY_ENCRYPTION_KEY!;
    
        // Generate a random salt for this specific user’s encryption
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(16);  
        const key = crypto.scryptSync(masterKey, salt, 32);

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        // Combine all parts (salt, iv, authTag, ciphertext)
        return [
            salt.toString('hex'),
            iv.toString('hex'),
            authTag.toString('hex'),
            encrypted
        ].join(':');
    }

    decryptRecoveryData(encryptedData: string, userId: string): any {
        // const parts = encryptedData.split(':');
        // const iv = Buffer.from(parts[0], 'hex');
        // const authTag = Buffer.from(parts[1], 'hex');
        // const encrypted = parts[2];

        // const key = crypto.scryptSync(process.env.RECOVERY_ENCRYPTION_KEY!, userId, 32);
        // const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        // decipher.setAuthTag(authTag);

        // let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        // decrypted += decipher.final('utf8');

        // return JSON.parse(decrypted);


        const parts = encryptedData.split(':');
        const salt = Buffer.from(parts[0], 'hex');
        const iv = Buffer.from(parts[1], 'hex');
        const authTag = Buffer.from(parts[2], 'hex');
        const encrypted = parts[3];

        const masterKey = process.env.RECOVERY_ENCRYPTION_KEY!;
        const key = crypto.scryptSync(masterKey, salt, 32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    }
}