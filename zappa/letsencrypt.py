#!/usr/bin/env python3
import atexit
from io import BytesIO
import shutil
import tempfile

import requests
import sewer.client
from sewer.crypto import AcmeKey, AcmeAccount
import sewer.dns_providers.route53


def create_chained_cert(sewer_client):
    cross_cert_url = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"
    cert = requests.get(cross_cert_url)

    chain = BytesIO()

    chain.write(cert.content)
    chain.write(sewer_client.acme_csr.public_bytes())
    return chain.getvalue()


def get_cert_and_update_domain(
    zappa_instance,
    lambda_name,
    api_stage,
    domain=None,
    manual=False,
):
    """
    Main cert installer path.
    """

    try:
        dns_class = sewer.dns_providers.route53.Route53Dns()

        # client.get_certificate()

        # Here endith the

        cert_key = AcmeKey.create("rsa2048")

        account = AcmeAccount.create("rsa2048")

        certificate_private_key = account.to_pem()

        client = sewer.client.Client(
            domain_name=domain,
            provider=dns_class,
            account=account,
            is_new_acct=True,
            cert_key=cert_key
        )

        certificate = client.get_certificate()

        certificate_body = certificate

        certificate_chain = create_chained_cert(client)

        if not manual:
            if domain:
                if not zappa_instance.get_domain_name(domain):
                    zappa_instance.create_domain_name(
                        domain_name=domain,
                        certificate_name=domain + "-Zappa-LE-Cert",
                        certificate_body=certificate_body,
                        certificate_private_key=certificate_private_key,
                        certificate_chain=certificate_chain,
                        certificate_arn=None,
                        lambda_name=lambda_name,
                        stage=api_stage
                    )
                    print("Created a new domain name. Please note that it can take up to 40 minutes for this domain to be created and propagated through AWS, but it requires no further work on your part.")
                else:
                    zappa_instance.update_domain_name(
                        domain_name=domain,
                        certificate_name=domain + "-Zappa-LE-Cert",
                        certificate_body=certificate_body,
                        certificate_private_key=certificate_private_key,
                        certificate_chain=certificate_chain,
                        certificate_arn=None,
                        lambda_name=lambda_name,
                        stage=api_stage
                    )
        else:
            print("Cerificate body:\n")
            print(certificate_body)

            print("\nCerificate private key:\n")
            print(certificate_private_key)

            print("\nCerificate chain:\n")
            print(certificate_chain)

    except Exception as e:
        print(e)
        return False

    return True


__tempdir = None


def gettempdir():
    """
    Lazily creates a temporary directory in a secure manner. When Python exits,
    or the cleanup() function is called, the directory is erased.
    """
    global __tempdir
    if __tempdir is not None:
        return __tempdir
    __tempdir = tempfile.mkdtemp()
    return __tempdir


@atexit.register
def cleanup():
    """
    Delete any temporary files.
    """
    global __tempdir
    if __tempdir is not None:
        shutil.rmtree(__tempdir)
        __tempdir = None
