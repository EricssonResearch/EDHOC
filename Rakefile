require "rexml/document"
require "rexml/xpath"
include REXML

XMLFILE = "draft-selander-ace-cose-ecdhe.xml"
CDDLFILE = "ecdhe.cddl"

CDDLFILE_p1 = "ecdhe_extract.cddl"

task :verify => [CDDLFILE, XMLFILE] do |t|
  doc = Document.new(File.read(XMLFILE))
  XPath.each(doc, "//artwork[@type='CBORdiag']/text()") do |snip|
    IO.popen("diag2cbor.rb | cddl #{CDDLFILE} v -", 'r+') do |io|
      io.write snip.to_s.gsub("nil", "null").gsub(/\n\s*/, "")
      io.close_write
      p io.read
    end
  end
end

task :gen => CDDLFILE  do |t|
  sh "cddl #{t.source} g"
end

file CDDLFILE_p1 => [XMLFILE] do |t|
  doc = Document.new(File.read(t.source))
  File.open(t.name, "w") do |f|
    f.puts XPath.match(doc, "//artwork[@type='CDDL']/text()").to_a.join.gsub("&gt;", ">")
  end
end

file CDDLFILE => ["prefix.cddl", CDDLFILE_p1, "cose.cddl"] do |t|
  doc = File.open(t.name, "w")
  t.prerequisites.each do |src|
    doc2 = File.read(src)
    doc.puts doc2
  end
end
