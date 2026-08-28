const path = require('path');
const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');

// The library lives one directory up and is linked with "file:..", so metro has
// to watch it and must be told to resolve react/react-native from the example's
// own node_modules or it will bundle two copies.
const root = path.resolve(__dirname, '..');

/**
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root],
  resolver: {
    nodeModulesPaths: [
      path.resolve(__dirname, 'node_modules'),
      path.resolve(root, 'node_modules'),
    ],
    extraNodeModules: {
      '@ammarahmed/react-native-sodium': root,
      react: path.resolve(__dirname, 'node_modules/react'),
      'react-native': path.resolve(__dirname, 'node_modules/react-native'),
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
