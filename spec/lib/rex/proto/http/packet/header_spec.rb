
require 'spec_helper'
require 'rex/proto/http/packet/header'

describe Rex::Proto::Http::Packet::Header do

	it_behaves_like "hash with insensitive keys"

	describe "#from_s" do
		let :original_str do
			"POST /foo HTTP/1.0\r\n" \
			"Content-Length: 0\r\n" \
			"Foo: Bar\r\n" \
			"Bar: Baz\r\n" \
			"Fold-me: fold one\r\n" \
			"Fold-me: fold two\r\n" \
			"\r\n"
		end

		before :each do
			subject.from_s(original_str)
		end

		it "should create keys and values for each header" do
			subject['Foo'].should == "Bar"
			subject['Content-Length'].should == "0"
		end
		
		it "should fold headers" do
			subject['Fold-me'].should == "fold one, fold two"
		end
	end

	describe "#to_s" do
		before :each do
			subject.from_s(original_str)
		end
		context "without folding" do
			let :original_str do
				"POST /foo HTTP/1.0\r\n" \
				"Foo: Bar\r\n" \
				"Bar: Baz\r\n" \
				"\r\n"
			end

			it "should return the same string" do
				subject.to_s.should == original_str
			end
		end
		context "with folding" do
			let :original_str do
				"POST /foo HTTP/1.0\r\n" \
				"Foo: Bar\r\n" \
				"Foo: Baz\r\n" \
				"Foo: Bab\r\n" \
				"\r\n"
			end
			it "should produce an equivalent string" do
				pending "who knows"
				folded =
					"POST /foo HTTP/1.0\r\n" \
					"Foo: Bar, Baz, Bab\r\n" \
					"\r\n"
				subject.to_s.should == folded
			end
		end
	end

end
