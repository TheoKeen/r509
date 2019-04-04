#!/usr/bin/env ruby

require 'rubygems'
require 'r509'
require 'r509/trollop'
require 'r509/signature_logger'
require 'r509/trollop'
require 'r509/testprofile'
require 'r509/cahelper'
require 'io/console'

#puts R509.CreateCAProfile
#R509.testprofiles


ARGV[0] = "--operation=CSR"
ARGV[1] = "--ca=test"
ARGV[2] = "--subject=/CN=Test Root CA/O=Org/C=NL/ST=NH/L=Amsterdam"


opts = R509::Trollop.options do
  opt :operation, "Operation Type on CA. Valid values: 'CER' (Sign cert from CRL), CRL (Create CRL), CSR (Create new CSR)", :type => :string
  opt :ca, "CA to operate on. CA must exist in config file", :type => :string
  opt :profile, "Filename of profile to use for certificate creation (operation 'CER')", :type => :string
  opt :subject, "X509 subject / delimited. Example: /CN=test.example.net/O=Org/C=NL/ST=NH/L=Amsterdam", :type => :string
  opt :san, "Subject Alternative Name Example: test.example,*.example.net", :type => :string
  opt :message_digest, "Message digest to use. sha1, sha224, sha256, sha384, sha512, md5", :type => :string, :default => 'sha256'
  opt :duration, "Sign the certificate with the duration (in days) specified.", :type => :integer
  opt :bits, "Bit length of generated key. Ignored for EC.", :type => :integer, :default => 2048
  opt :out, "File name to save generated CSR or certificate", :type => :string
  version "r509 #{R509::VERSION}"
end

ops = opts[:operation]

if opts[:operation].nil? || opts[:ca].nil?
  puts "operation and ca are required options"
  exit
elsif !(opts[:operation].upcase == "CER" || opts[:operation].upcase == "CSR" || opts[:operation].upcase == "CRL")
  puts "invalid operation specified. Please use one of the following values for operation: CER/CSR/CRL"
  exit
end


if opts[:operation].upcase == "CSR"
  if opts[:subject].nil? || opts[:subject].to_s.strip.empty?
    puts "Option subject is required for operation CSR. Please provide subject"
    exit
  end

 # subject = ["ss" 'ss']
  subject = R509.SubjectFromString(opts[:subject])
  
  csr = R509::CSR.new(
    :subject => subject,
    :bit_length => opts[:bits],
#    :type => opts[:type].upcase,
    :curve_name => opts[:curve_name],
    :san_names => (opts[:san] || "").split(',').map { |domain| domain.strip },
    :message_digest => opts[:message_digest]
    :PrivateKey => ca.ca_cert.key.key
  )

  puts csr.subject

  yaml_data = File.read "bin/configsoft.yaml"
  conf = R509::Config::CAConfig.from_yaml("test_ca", yaml_data)
  ca = R509::CertificateAuthority::Signer.new(conf)

  

  #slog = R509::SignatureLogger.new(conf)
  #slog.logsignature(cert)

end









#ops = ARGV[0]
puts "starting"


#yaml_data = File.read "bin/config.yaml"
yaml_data = File.read "bin/configsoft.yaml"
conf = R509::Config::CAConfig.from_yaml("test_ca", yaml_data)
ca = R509::CertificateAuthority::Signer.new(conf)

ext = []
# you can add extensions in an array. See R509::Cert::Extensions::*
ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)

csr = R509::CSR.new(
    :subject => {
      :CN => 'Keennews.nl',
      :O => 'Keennews',
      :L => 'KeenCity',
      :ST => 'NH',
      :C => 'NL'
    }
  )

  
  cert = ca.sign(
    :csr => csr,
    :extensions => ext
  )


#Display Cert

#myvar = slog.listlogs


