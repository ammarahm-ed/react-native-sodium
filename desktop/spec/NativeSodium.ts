import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  sodium_version_string(): Promise<string>;
  encrypt(password: Object, data: Object): Promise<Object>;
  decrypt(password: Object, cipher: Object): Promise<string>;
  encryptMulti(password: Object, data: Array<Object>): Promise<Array<Object>>;
  decryptMulti(password: Object, data: Array<Object>): Promise<Array<string>>;
  hashPassword(password: string, email: string): Promise<string>;
  deriveKey(password: string, salt: string | null): Promise<Object>;
  encryptFile(password: Object, data: Object): Promise<Object>;
  decryptFile(
    password: Object,
    cipher: Object,
    type: string,
  ): Promise<string>;
  hashFile(data: Object): Promise<string>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Sodium');
