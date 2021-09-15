export type Callback = (response: ImagePickerResponse) => any;

export interface ImageLibraryOptions {
  mediaType: MediaType;
  selectionLimit?: number;
  maxWidth?: number;
  maxHeight?: number;
  quality?: PhotoQuality;
  videoQuality?: AndroidVideoOptions | iOSVideoOptions;
  includeBase64?: boolean;
  password?:string;
  key?:string;
  salt?:string;
  encryptToFile?:boolean
}

export interface Asset {
  base64?: string;
  uri?: string;
  width?: number;
  height?: number;
  fileSize?: number;
  type?: string; //TODO
  fileName?: string;
  duration?: number;
  encryptionInfo:FileCipher
}

export type FileCipher = {
  salt?:string,
  hash?:string,
  hashType?:string,
  iv?:string,
  length?:number
  mime?:string,
  fileName?:string,
  uri?:string
}

export type PASSWORD = {
  key:string,
  salt:string
}

export type CIPHER = {
  salt:string,
  iv:string,
  length:number,
  cipher?:string
}

export interface CameraOptions extends ImageLibraryOptions {
  durationLimit?: number;
  saveToPhotos?: boolean;
  cameraType?: CameraType;
}

export interface ImagePickerResponse {
  didCancel?: boolean;
  errorCode?: ErrorCode;
  errorMessage?: string;
  assets?: Asset[];
}

export type PhotoQuality =
  | 0
  | 0.1
  | 0.2
  | 0.3
  | 0.4
  | 0.5
  | 0.6
  | 0.7
  | 0.8
  | 0.9
  | 1;
export type CameraType = 'back' | 'front';
export type MediaType = 'photo' | 'video' | 'mixed';
export type AndroidVideoOptions = 'low' | 'high';
export type iOSVideoOptions = 'low' | 'medium' | 'high';
export type ErrorCode = 'camera_unavailable' | 'permission' | 'others';
