require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name         = "react-native-sodium"
  s.version      = package['version']
  s.summary      = package['description']
  s.license      = package['license']

  s.authors      = package['author']
  s.homepage     = package['homepage']
  s.platform     = :ios, "15.1"

  s.source       = { :git => "https://github.com/lyubo/react-native-sodium.git", :tag => "v#{s.version}" }
  s.source_files  = ["ios/**/*.{h,m}","libsodium/libsodium-ios/**/*.{h,m}"]

  s.vendored_libraries = 'libsodium/libsodium-ios/lib/libsodium.a'
  s.xcconfig = { 'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/#{s.name}/**" }

  s.dependency 'React-Core'
  # RCTSodium.m imports MF_Base64Additions.h. This was never declared, so the
  # pod only built inside apps that happened to install Base64 for some other
  # reason.
  s.dependency 'Base64'
end
