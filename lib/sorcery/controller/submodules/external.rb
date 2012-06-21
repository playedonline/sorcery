module Sorcery
  module Controller
    module Submodules
      # This submodule helps you login users from external auth providers such as Twitter.
      # This is the controller part which handles the http requests and tokens passed between the app and the provider.
      module External
        def self.included(base)
          base.send(:include, InstanceMethods)
          Config.module_eval do
            class << self
              attr_reader :external_providers                           # external providers like twitter.
              attr_accessor :ca_file                                    # path to ca_file. By default use a internal ca-bundle.crt.
                                          
              def merge_external_defaults!
                @defaults.merge!(:@external_providers => [],
                                 :@ca_file => File.join(File.expand_path(File.dirname(__FILE__)), 'external/protocols/certs/ca-bundle.crt'))
              end
              
              def external_providers=(providers)
                providers.each do |provider|
                  include Providers.const_get(provider.to_s.split("_").map {|p| p.capitalize}.join(""))
                end
              end
            end
            merge_external_defaults!
          end
        end

        module InstanceMethods
          protected
          
          # sends user to authenticate at the provider's website.
          # after authentication the user is redirected to the callback defined in the provider config
          def login_at(provider, args = {})
            @provider = Config.send(provider)
            if @provider.has_callback?
              redirect_to @provider.login_url(params,session)
            else
              @provider.login(args)
            end
          end
          
          # tries to login the user from provider's callback
          def login_from(provider)
            @provider = Config.send(provider)
            @provider.process_callback(params,session)
            @user_hash = @provider.get_user_hash
            user = User.find_by_fb_id(@user_hash[:uid]) if (provider == 'facebook')
            if user ||= user_class.load_from_provider(provider,@user_hash[:uid])
              user.send("after_login_from_#{provider}",@user_hash) if user.respond_to?("after_login_from_#{provider}")
              reset_session
              auto_login(user)
              user
            end
          end

          # get provider access account
          def access_token(provider)
            @provider = Config.send(provider)
            @provider.access_token
          end
          
          # this method automatically creates a new user from the data in the external user hash.
          # The mappings from user hash fields to user db fields are set at controller config.
          # If the hash field you would like to map is nested, use slashes. For example, Given a hash like:
          #
          #   "user" => {"name"=>"moishe"}
          #
          # You will set the mapping:
          #
          #   {:username => "user/name"}
          #
          # And this will cause 'moishe' to be set as the value of :username field.
          # Note: Be careful. This method skips validations model.
          def create_from(provider)
            provider = provider.to_sym
            @provider = Config.send(provider)
            @user_hash = @provider.get_user_hash
            config = user_class.sorcery_config
            attrs = {}
            @provider.user_info_mapping.each do |k,v|
              if (varr = v.split("/")).size > 1
                attribute_value = varr.inject(@user_hash[:user_info]) {|hsh,v| hsh[v] } rescue nil
                attribute_value.nil? ? attrs : attrs.merge!(k => attribute_value)
              else
                attrs.merge!(k => @user_hash[:user_info][v])
              end
            end
            user_class.transaction do
              # changed by ehud to support converting guest users to registered ones
              #@user = user_class.new()
              attrs.each do |k,v|
                #using @current_user so it will use the generated guest user instead of creating a new one
                @current_user.send(:"#{k}=", v)
              end
              #@current_user.save!
              if @current_user.password.blank?
                 @current_user.password = Digest::MD5.hexdigest(Time.now.nsec.to_s + rand.to_s + Rails.application.config.secret_token)
                # autogenerate a password so the validation will pass. This is needed for facebook users who don't really have a password.
                # The original code skipped validations which is not a good idea.
              end
              @current_user.save_to_cache(:flush_immediately=>true)
              user_class.sorcery_config.authentications_class.create!({config.authentications_user_id_attribute_name => @current_user.id, config.provider_attribute_name => provider, config.provider_uid_attribute_name => @user_hash[:uid]})
              @current_user.send("after_created_from_#{provider}") if @current_user.respond_to?("after_created_from_#{provider}")
            end
            @current_user
          end
        end
      end
    end
  end
end
