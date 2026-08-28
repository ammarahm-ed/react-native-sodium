/**
 * A faithful port of the file surface of
 * notesnook/apps/mobile/app/common/filesystem/io.ts.
 *
 * readEncrypted keeps the app's swallow-and-return-undefined behaviour on
 * purpose: several tests assert on what the app would actually observe.
 */
import Sodium from '@ammarahmed/react-native-sodium';
import {Platform} from 'react-native';
import ReactNativeBlobUtil from 'react-native-blob-util';
import {cacheDir, randomId} from '../util';
import {SerializedKey} from './encryption';

export const IOS_APPGROUPID = undefined;

export type FileEncryptionMetadata = {
  iv: string;
  salt: string;
  length: number;
  alg: string;
  hash: string;
  hashType: string;
  chunkSize: number;
  size: number;
};

export async function createCacheDir() {
  if (!(await ReactNativeBlobUtil.fs.exists(cacheDir))) {
    await ReactNativeBlobUtil.fs.mkdir(cacheDir);
  }
}

export async function exists(filename: string) {
  return ReactNativeBlobUtil.fs.exists(`${cacheDir}/${filename}`);
}

export async function hashBase64(data: string) {
  const hash = await Sodium.hashFile({
    type: 'base64',
    data,
    uri: '',
  });
  return {
    hash: hash,
    type: 'xxh64',
  };
}

export async function writeEncryptedBase64(
  data: string,
  encryptionKey: SerializedKey,
  _mimeType: string,
) {
  await createCacheDir();
  const filepath = cacheDir + `/${randomId('imagecache_')}`;
  await ReactNativeBlobUtil.fs.writeFile(filepath, data, 'base64');
  const output = await Sodium.encryptFile(encryptionKey, {
    uri: Platform.OS === 'ios' ? filepath : 'file://' + filepath,
    type: 'url',
  });

  ReactNativeBlobUtil.fs.unlink(filepath).catch(() => {
    /* empty */
  });

  return {
    ...output,
    alg: 'xcha-stream',
  };
}

export async function readEncrypted(
  filename: string,
  key: SerializedKey,
  cipherData: Partial<FileEncryptionMetadata> & {outputType: 'base64' | 'text'},
) {
  const path = `${cacheDir}/${filename}`;

  try {
    if (!(await exists(filename))) {
      return;
    }

    const output = await Sodium.decryptFile(
      key,
      {
        ...cipherData,
        hash: filename,
        appGroupId: IOS_APPGROUPID,
      } as any,
      cipherData.outputType === 'base64' ? 'base64' : 'text',
    );

    return output;
  } catch (e) {
    ReactNativeBlobUtil.fs.unlink(path).catch(() => {
      /* empty */
    });
    // The app logs and returns undefined here, so a native failure is invisible
    // to the caller. Tests that need the real error call Sodium directly.
    throw e;
  }
}
