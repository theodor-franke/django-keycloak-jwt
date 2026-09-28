import django_keycloak_jwt


def test_package_importable() -> None:
    assert django_keycloak_jwt.__version__
