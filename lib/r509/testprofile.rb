module R509
  
  def TestProfiles
    profile = R509::Config::CertProfile.new(
      :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(
        :ca => false
      ),
      :key_usage => R509::Cert::Extensions::KeyUsage.new(
        :value => ['digitalSignature','keyEncipherment']
      ),
      :extended_key_usage => R509::Cert::Extensions::ExtendedKeyUsage.new(
        :value => ['serverAuth','clientAuth']
      ),
      :authority_info_access => R509::Cert::Extensions::AuthorityInfoAccess.new(
        :ocsp_location => [{:type => 'URI', :value => 'http://ocsp.example.net'}]
      ),
      :certificate_policies => R509::Cert::Extensions::CertificatePolicies.new(
        :value => [{:policy_identifier => '1.23.3.4.4.5.56'}]
      ),
      :crl_distribution_points => R509::Cert::Extensions::CRLDistributionPoints.new(
        :value => [{:type => 'URI', :value => 'http://pki.example.net/crl/ca.crl'}]
      ),
      :inhibit_any_policy => R509::Cert::Extensions::InhibitAnyPolicy.new(
        :value => 0
      ),
      :name_constraints => R509::Cert::Extensions::NameConstraints.new(
        :permitted => [{:type => 'dirName', :value => { :CN => 'test' } }]
      ),
      :ocsp_no_check => R509::Cert::Extensions::OCSPNoCheck.new(:value => true),
      :policy_constraints => R509::Cert::Extensions::PolicyConstraints.new(
        :require_explicit_policy=> 1
      ),
      :subject_item_policy => R509::Config::SubjectItemPolicy.new(
        "CN" => {:policy => "required"},
        "O" => {:policy => "optional"},
        "OU" => {:policy => "match", :value => "Engineering" }
      ),
      :default_md => "SHA256",
      :allowed_mds => ["SHA256","SHA512"]
    )



    myyaml = profile.to_yaml
    myyamlfile = "C:/dev/log/testprofile.yaml"
    File.write(myyamlfile, myyaml) 
    profile2 = profile = R509::Config::CertProfile.new()
    profile2 = YAML.load(File.new(myyamlfile))
    puts profile2.class

  end
  module_function :TestProfiles
  

  def CreateCAProfile
    caprofile = R509::Config::CertProfile.new(
      :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(
        :ca => true
      ),
      :key_usage => R509::Cert::Extensions::KeyUsage.new(
        :value => ['cRLSign','digitalSignature', 'keyCertSign']
      ),
      :authority_info_access => R509::Cert::Extensions::AuthorityInfoAccess.new(
        :ocsp_location => [{:type => 'URI', :value => 'http://ocsp.example.net'}]
      ),
      :certificate_policies => R509::Cert::Extensions::CertificatePolicies.new(
        :value => [{:policy_identifier => '1.23.3.4.4.5.56'}]
      ),
      :crl_distribution_points => R509::Cert::Extensions::CRLDistributionPoints.new(
        :value => [{:type => 'URI', :value => 'http://pki.example.net/crl/ca.crl'}]
      ),
      :default_md => "SHA256",
      :allowed_mds => ["SHA256","SHA512"]
    )



    caprofileyaml = caprofile.to_yaml
    myyamlfile = "C:/dev/log/caprofile.yaml"
    File.write(myyamlfile, caprofileyaml) 
    profile2 = profile = R509::Config::CertProfile.new()
    profile2 = YAML.load(File.new(myyamlfile))
    puts profile2.class

  end
  module_function :CreateCAProfile

end