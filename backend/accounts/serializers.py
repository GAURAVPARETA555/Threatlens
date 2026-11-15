from django.contrib.auth import get_user_model
from rest_framework import serializers

from django.contrib.auth.password_validation import (
    validate_password as django_validate_password,
)
User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        min_length=6
    )

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
        ]
    def validate_password(self, value):
        candidate_user = User(
            username=self.initial_data.get("username", ""),
            email=self.initial_data.get("email", ""),
        )

        django_validate_password(value, candidate_user)
        return value
    def create(self, validated_data):
        password = validated_data.pop("password")

        user = User( role="viewer",**validated_data)
        user.set_password(password)
        user.save()

        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "role",
        ]