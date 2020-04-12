declare module "react-native-sodium" {
  export function sodium_version_string(): Promise<string>;
  
  export function encrypt(password:string,data:string):Promise<object>;

  export function decrypt(password:string,data:object):Promise<string>;

  export function deriveKey(password:string):Promise<object>;
}
