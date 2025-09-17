from setuptools import setup

setup(
    name="password-checker",
    version="1.0.0",
    py_modules=["password_checker"],
    entry_points={
        "console_scripts": [
            "password-checker=password_checker:main",
        ],
    },
    author="Param",
    author_email="technicalparam@outlook.com",
    description="A Python password strength and leak check tool",
    license="MIT",
)
