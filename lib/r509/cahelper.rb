module R509

def SubjectFromString(value)
    subject = []
    value.chomp.split('/').each do |item|
      if item != ''
        subject.push item.split('=')[0..1]
      end
    end
    return subject
  end
  module_function :SubjectFromString


end