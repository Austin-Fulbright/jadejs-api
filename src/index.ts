import EventEmitter from "events";
import { encode, decode } from "cbor2";
import bs58check from 'bs58check';
import createHash from 'create-hash';



export function get_multisig_name(multisig: BitcoinMultisig): string {
    const { descriptor: { threshold, signers }, network } = multisig;
    const type = 'multisig';
    // Concatenate script-type, threshold, and all signers fingerprints and derivation paths (sorted)
    let summary = type + '|' + threshold + '|';
    for (const { fingerprint, path } of signers) {
        summary += fingerprint + '|' + path + '|';
    }
    // Hash it, get the first 6-bytes as hex, prepend with 'hwi'
    const hash_summary = createHash('sha256').update(summary).digest('hex');
    return 'hwi' + hash_summary.slice(0, 12);
}

export function getRootFingerprint(xpub: string): string {
    const rawBytes = bs58check.decode(xpub);
    if (rawBytes.length !== 78) {
      throw new Error('Invalid extended key length');
    }
    const pubkey = rawBytes.slice(45, 78);
    const sha256Hash = createHash('sha256').update(pubkey).digest();
    const ripemd160Hash = createHash('ripemd160').update(sha256Hash).digest();
  
    return ripemd160Hash.slice(0, 4).toString('hex');
}
  


export interface RPCRequest {
    id: string;
    method: string;
    params?: any;
  };
  
export interface RPCResponse {
    id: string;
    result?: any;
    error?: {
      code: number;
      message: string;
      data?: any;
    };
  };
  

export interface SerialPortOptions {
    device?: string;
    baudRate?: number;
    timeout?: number;
};

export interface IDevice extends EventEmitter {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  sendMessage(message: any): Promise<void>;
  onMessage(callback: (message: any) => void): void;
};


export interface BitcoinMultisig {
    network: string;
    multisig_name: string;
    descriptor: {
        variant: string;
        sorted: boolean;
        threshold: number;
        signers: Signer[];
        master_blinding_key: any;
    };
};

export interface Signer {
    xpub: string;
    derivation: number[];
    fingerprint: string;
    path: number[];
}

export interface IJade {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  buildRequest(id: string, method: string, params?: any): RPCRequest;
  makeRPCCall(request: RPCRequest, long_timeout: boolean): Promise<RPCResponse>;
};

export class WebSerialPort extends EventEmitter implements IDevice {
    private options: SerialPortOptions;
    private port: any | null = null;
    private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    private receivedBuffer: Uint8Array = new Uint8Array(0);
  
    constructor(options: SerialPortOptions) {
      super();
      this.options = options;
    }
   
    /**
     * Clears any accumulated bytes from the input buffer.
     */
    drain(): void {
      this.receivedBuffer = new Uint8Array(0);
    }
  
    async connect(): Promise<void> {
      try {
        const serial = (navigator as any).serial;
        if (!serial) {
          throw new Error('Web Serial API is not supported in this browser.');
        }
        const ports: any[] = await serial.getPorts();
        if (ports.length === 0) {
          this.port = await serial.requestPort();
        } else {
          this.port = ports[0];
        }
        if (!this.port) {
          throw new Error('No serial port selected.');
        }
        await this.port.open({ baudRate: this.options.baudRate || 115200 });
        this.reader = this.port.readable?.getReader() || null;
        if (this.reader) {
          this.readLoop();
        }
      } catch (error) {
        console.error('[WebSerialPort] Failed to connect:', error);
        throw error;
      }
    }
  
    private async readLoop(): Promise<void> {
      if (!this.reader) return;
      try {
        while (true) {
          const { value, done } = await this.reader.read();
          if (done) {
            break;
          }
          if (value) {
            this.receivedBuffer = this.concatBuffers(this.receivedBuffer, value);
            this.processReceivedData();
          }
        }
      } catch (error) {
        console.error('[WebSerialPort] Read error:', error);
      } finally {
        if (this.reader) {
          this.reader.releaseLock();
          this.reader = null;
        }
      }
    }
  
    /**
     * Process the accumulated buffer by trying to decode slices with increasing length.
     * When a valid CBOR message is decoded that contains one of the expected keys,
     * it is emitted as a 'message' event.
     */
    private processReceivedData(): void {
      let index = 1;
      while (index <= this.receivedBuffer.length) {
        try {
          const sliceToTry = this.receivedBuffer.slice(0, index);
          const decoded = decode(sliceToTry);
          if (
            decoded &&
            typeof decoded === 'object' &&
            (('error' in decoded) || ('result' in decoded) || ('log' in decoded) || ('method' in decoded))
          ) {
            this.emit('message', decoded);
          } else {
            console.warn('[WebSerialPort] Decoded message missing expected keys:', decoded);
          }
          // Remove the processed bytes.
          this.receivedBuffer = this.receivedBuffer.slice(index);
          index = 1;
        } catch (error: any) {
          
          if (
            error.message &&
            (error.message.includes('Offset is outside') ||
             error.message.includes('Insufficient data') ||
             error.message.includes('Unexpected end of stream'))
          ) {
            index++;
            if (index > this.receivedBuffer.length) {
              break;
            }
          } else {
            console.error('[WebSerialPort] CBOR decode error:', error);
            this.receivedBuffer = new Uint8Array(0);
            break;
          }
        }
      }
    }
  
    private concatBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
      const result = new Uint8Array(a.length + b.length);
      result.set(a);
      result.set(b, a.length);
      return result;
    }
  
    async disconnect(): Promise<void> {
      try {
        if (this.reader) {
          await this.reader.cancel();
        }
        if (this.port) {
          await this.port.close();
        }
        this.port = null;
        this.reader = null;
        console.log('[WebSerialPort] Disconnected successfully.');
      } catch (error) {
        console.error('[WebSerialPort] Error during disconnect:', error);
      }
    }
  
    async sendMessage(message: any): Promise<void> {
      try {
        if (!this.port || !this.port.writable) {
          throw new Error('Port not available');
        }
        const encoded = encode(message);
        const writer = this.port.writable.getWriter();
        await writer.write(encoded);
        writer.releaseLock();
      } catch (error) {
        console.error('[WebSerialPort] Failed to send message:', error);
        throw error;
      }
    }
  
    onMessage(callback: (message: any) => void): void {
      this.on('message', callback);
    }
  }

export class JadeInterface extends EventEmitter implements IJade {
  private impl: IDevice;

  constructor(impl: IDevice) {
    super();
    if (!impl) throw new Error('A serial/ble implementation is required');
    this.impl = impl;
  }

  async connect(): Promise<void> {
    return this.impl.connect();
  }

  async disconnect(): Promise<void> {
    return this.impl.disconnect();
  }

  buildRequest(id: string, method: string, params?: any): RPCRequest {
    return { id, method, params };
  }

  async makeRPCCall(request: RPCRequest, long_timeout: boolean = false): Promise<RPCResponse> {
    // Validate request fields
    if (!request.id || request.id.length > 16) {
      throw new Error('Request id must be non-empty and less than 16 characters');
    }
    if (!request.method || request.method.length > 32) {
      throw new Error('Request method must be non-empty and less than 32 characters');
    }
    
    // Send the RPC message (encoded as CBOR)
    await this.impl.sendMessage(request);
    
    return new Promise<RPCResponse>((resolve, reject) => {
      const onResponse = (msg: RPCResponse) => {
        if (msg && msg.id === request.id) {
          this.impl.removeListener('message', onResponse);
          if (timeoutId) clearTimeout(timeoutId);
          resolve(msg);
        }
      };
      this.impl.onMessage(onResponse);
      
      // If not a long timeout, set a timeout to reject the promise
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      if (!long_timeout) {
        timeoutId = setTimeout(() => {
          this.impl.removeListener('message', onResponse);
          reject(new Error('RPC call timed out'));
        }, 5000); // 5000 milliseconds timeout
      }
    });
  }
}
  



export function add(a: number, b: number): number {
    return a + b;
}

export class JadeAPI {
  private iface: IJade;

  constructor(iface: IJade) {
    if (!iface) throw new Error('A valid JadeInterface instance is required');
    this.iface = iface;
  }

  static createSerial(device?: string, baudRate: number = 115200, timeout?: number): JadeAPI {
    const options = { device, baudRate, timeout };
    const serial = new WebSerialPort(options);
    const iface = new JadeInterface(serial);
    return new JadeAPI(iface);
  }

  async connect(): Promise<void> {
    return this.iface.connect();
  }

  async disconnect(): Promise<void> {
    return this.iface.disconnect();
  }

  private async jadeRpc(
    method: string,
    params?: any,
    id?: string,
    long_timeout: boolean = false,
    http_request_fn?: (params: any) => Promise<{ body: any }>
  ): Promise<any> {
    const requestId = id || Math.floor(Math.random() * 1000000).toString();
    const request = this.iface.buildRequest(requestId, method, params);
    const reply = await this.iface.makeRPCCall(request, long_timeout);
    
    if (reply.error) {
      throw new Error(`RPC Error ${reply.error.code}: ${reply.error.message}`);
    }
    if (reply.result &&
        typeof reply.result === 'object' &&
        'http_request' in reply.result) {
      
      if (!http_request_fn) {
        throw new Error('HTTP request function not provided');
      }
      
      const httpRequest = reply.result['http_request'];
      const httpResponse = await http_request_fn(httpRequest['params']);
      return this.jadeRpc(
        httpRequest['on-reply'],
        httpResponse['body'],
        undefined,
        long_timeout,
        http_request_fn
      );
    }
    
    return reply.result;
  }
  

  // Public API methods


  //basic RPC

  ping(): Promise<number> {
    return this.jadeRpc('ping');
  }

  getVersionInfo(nonblocking: boolean = false): Promise<any> {
    const params = nonblocking ? { nonblocking: true } : undefined;
    return this.jadeRpc('get_version_info', params);
  }

  logout(): Promise<boolean> {
    return this.jadeRpc('logout');
  }

  //wallet management
  addEntropy(entropy: any): Promise<any> {
    const params = { entropy };
    return this.jadeRpc('add_entropy', params);
  }

  setEpoch(epoch?: number): Promise<any> {
    const params = { epoch: epoch !== undefined ? epoch : Math.floor(Date.now() / 1000) };
    return this.jadeRpc('set_epoch', params);
  }

  setMnemonic(mnemonic: string, passphrase?: string, temporaryWallet: boolean = false): Promise<boolean> {
    const params = { mnemonic, passphrase, temporary_wallet: temporaryWallet };
    return this.jadeRpc('set_mnemonic', params);
  }

  setSeed(seed: Uint8Array): Promise<boolean> {
    const params = { seed };
    return this.jadeRpc('set_seed', params);
  }

  runRemoteSelfCheck(): Promise<Number> {

    return this.jadeRpc('debug_selfcheck', undefined, undefined, true);
  }

  

  //camera

  captureImageData(check_qr: boolean = false): Promise<any> {
    const params = { check_qr };
    return this.jadeRpc('debug_capture_image_data', params);
  }

  scanQR(image: any): Promise<any> {

    const params = {'image': image};
    return this.jadeRpc('debug_scan_qr', params);

  }

  //advanced wallet operations

  cleanReset(): Promise<boolean> {

    return this.jadeRpc('debug_clean_reset');
  }

  getbip85bip39Entropy(num_words: number, index: number, pubkey: any): Promise<any>{
    const params = {num_words, index, pubkey};
    return this.jadeRpc('get_bip85_bip39_entropy', params);
  }

  getbip85rsaEntropy(key_bits: number, index: number, pubkey: any): Promise<any>{

    const params = {key_bits, index, pubkey};
    return this.jadeRpc('get_bip85_rsa_entropy', params);
  }

  setPinserver(urlA?: string, urlB?: string, pubkey?: Uint8Array, cert?: Uint8Array): Promise<boolean> {
    const params: any = {};
    if (urlA !== undefined || urlB !== undefined) {
      params['urlA'] = urlA;
      params['urlB'] = urlB;
    }
    if (pubkey !== undefined) {
      params['pubkey'] = pubkey;
    }
    if (cert !== undefined) {
      params['certificate'] = cert;
    }
    return this.jadeRpc('update_pinserver', params);
  }


  resetPinserver(reset_details: boolean, reset_certificate: boolean): Promise<boolean> {
    const params = { reset_details, reset_certificate };
    return this.jadeRpc('update_pinserver', params);
  }

  authUser(
    network: string,
    http_request_fn?: (params: any) => Promise<{ body: any }>,
    epoch?: number
  ): Promise<boolean> {
    const params = {
      network,
      epoch: epoch !== undefined ? epoch : Math.floor(Date.now() / 1000)
    };
    return this.jadeRpc('auth_user', params, undefined, true, http_request_fn);
  }

  registerOtp(otp_name: string, otp_uri: string): Promise<boolean>{
    const params = {name: otp_name, uri: otp_uri};
    return this.jadeRpc('register_otp', params);
  }

  getOtpCode(otp_name: string, value_override?: number): Promise<number> {
    const params: any = { name: otp_name };
    if (value_override !== undefined) {
      params.override = value_override;
    }
    return this.jadeRpc('get_otp_code', params);
  }


  getXpub(network: string, path: number[]): Promise<any>{
    const params = {network, path};
    return this.jadeRpc('get_xpub', params);
  }


  getRegisteredMultisigs(): Promise<any>{
    return this.jadeRpc('get_registered_multisigs');
  }

  getRegisteredMultisig(multisig_name: string, as_file: boolean = false): Promise<any> {
    const params = {
      multisig_name,
      as_file
    }
    return this.jadeRpc('get_registered_multisig', params);
  }

  registerMultisig(network: string, multisig_name: string, variant: string, sorted_keys: boolean, threshold: number, signers: any, master_blinding_key?: any): Promise<boolean>{

    const params = {
      network,
      multisig_name,
      descriptor: {
        variant,
        sorted: sorted_keys,
        threshold,
        signers,
        master_blinding_key: master_blinding_key != undefined ? master_blinding_key : null
      }
    };

    return this.jadeRpc('register_multisig', params);
  }

  signPSBT(network: string, psbt: any): Promise<any> {

    const params = {
      network, psbt
    }

    return this.jadeRpc('sign_psbt', params);
  }

  getMultisigReceiveAddress(network: string, multisig_name: string, paths: number[][]): Promise<any>{
    
    const params = {
      network, multisig_name, paths
    }
    return this.jadeRpc('get_receive_address', params);
  }
}