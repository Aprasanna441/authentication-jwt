from rest_framework import serializers
from myapp.models import User 
from rest_framework.exceptions  import ValidationError
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from myapp.utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        if password2 != password:
            raise serializers.ValidationError("Password and Confirm Password doesnt match")

        return attrs
    
    def create(self,validate_data):
        return User.objects.create_user(**validate_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        fields=['email','password']
        model=User


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name']

class UserChangePasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    
    class Meta:
        fields=['password','password2']

    def validate(self, attrs):
        user=self.context.get('user')
        password=attrs.get('password')
        password2=attrs.get('password2')
        if password!=password2:
            raise serializers.ValidationError("Password and confirm password didnt match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        fields=['email']

    def validate(self,attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            link='http://localhost:8000/api/user/reset/'+uid+'/'+token
            print(link)
            #send_mail(username,to,from,subject ) wala code
            body="Click the link to reset your password"
            data={
                'subject':'Reset your password' ,
                'body' :link,
                'to_email':user.email
                
            }
            Util.send_mail(data)

            return attrs


        else:
            raise ValidationError('Not a registered User')
        
        
class UserPasswordResetSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    
    class Meta:
        fields=['password','password2']

    def validate(self, attrs):
        try:  ## done to prevent unicode decode
            uid=self.context.get('uid')
            token=self.context.get('token')

            password=attrs.get('password')
            password2=attrs.get('password2')
            if password!=password2:
             raise serializers.ValidationError("Password and confirm password didnt match")
            id=smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
             raise ValidationError("Token is not valid or not matching with the user")
        
            user.set_password(password)
            user.save()
            return attrs
        
    
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check(user,token)
            raise ValidationError("Token is not valid /expired/didnt match")









