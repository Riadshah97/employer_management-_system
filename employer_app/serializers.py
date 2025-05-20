from rest_framework import serializers
from .models import User, Employer
from django.utils.translation import gettext_lazy as _

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name')
        read_only_fields = ('id',)

class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password', 'confirm_password', 'first_name', 'last_name')
        
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError(_("Passwords don't match"))
        return data
        
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class EmployerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employer
        fields = ('id', 'company_name', 'contact_person_name', 'email', 
                  'phone_number', 'address', 'created_at')
        read_only_fields = ('id', 'created_at',)

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)
