#!/usr/bin/env ruby
require 'openssl'


root_ca = OpenSSL::X509::Certificate.new
root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
root_ca.serial = 1
root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
root_ca.issuer = root_ca.subject # root CA's are "self-signed"
root_ca.not_before = Time.now
root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = root_ca
ef.issuer_certificate = root_ca
root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))


#begin
#Load engine and Private Key
engine = OpenSSL::Engine.by_id("dynamic") do |e|
    e.ctrl_cmd("SO_PATH","c:/dev/bin/pkcs11.dll")
    e.ctrl_cmd("ID","pkcs11")
    e.ctrl_cmd("LIST_ADD","1")
    e.ctrl_cmd("LOAD")
    e.ctrl_cmd("PIN","123456")
    e.ctrl_cmd("MODULE_PATH", "c:/dev/SoftHSM2/lib/softhsm2-x64.dll")
end
root_key = engine.load_private_key("pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=c13db240b071fa33;token=R509SoftTest")
#=end
#root_key = OpenSSL::PKey::RSA.new(2048)
root_ca.public_key = root_key.public_key

root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

# Output in PEM format (aka base64-encoded DER)
puts root_ca.to_pem

File.write('bin\\certs\\rootcasoft.pem', root_ca.to_pem)