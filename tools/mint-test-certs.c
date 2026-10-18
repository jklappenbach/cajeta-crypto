/*
 * Mints the TLS test fixtures in src/test/cajeta/dev/cajeta/crypto/selftest/
 * TestCerts.cajeta: self-signed P-256 certificates with their private keys,
 * written as Cajeta string constants. The keys protect nothing; they exist so
 * the TLS tests need no openssl CLI and no harness at run time.
 *
 *   cc tools/mint-test-certs.c -lcrypto -o /tmp/mint && /tmp/mint > \
 *       src/test/cajeta/dev/cajeta/crypto/selftest/TestCerts.cajeta
 *
 * The valid certificates run 100 years from the day they were minted; the
 * expired one ended a year before it.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void emit(const char *name, const char *pem, long len) {
    printf("    static String %s =\n", name);
    long i = 0;
    while (i < len) {
        long j = i;
        while (j < len && pem[j] != '\n') j++;
        printf("        \"%.*s\\n\"%s\n", (int) (j - i), pem + i, j + 1 < len ? " +" : ";");
        i = j + 1;
    }
}

static int mint(const char *cn, long before, long after, const char *certName, const char *keyName) {
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    X509 *x = X509_new();
    if (!pkey || !x) return 1;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), before);
    X509_gmtime_adj(X509_getm_notAfter(x), after);
    X509_set_pubkey(x, pkey);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) cn, -1, -1, 0);
    X509_set_subject_name(x, name);
    X509_set_issuer_name(x, name);
    X509_NAME_free(name);
    char san[128];
    snprintf(san, sizeof san, "DNS:%s", cn);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (!ext) return 1;
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    if (!X509_sign(x, pkey, EVP_sha256())) return 1;
    BIO *cb = BIO_new(BIO_s_mem());
    BIO *kb = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(cb, x) || !PEM_write_bio_PrivateKey(kb, pkey, NULL, NULL, 0, NULL, NULL)) return 1;
    char *p;
    long n = BIO_get_mem_data(cb, &p);
    emit(certName, p, n);
    n = BIO_get_mem_data(kb, &p);
    emit(keyName, p, n);
    BIO_free(cb);
    BIO_free(kb);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return 0;
}

int main(void) {
    const long year = 365L * 24 * 3600;
    puts("package dev.cajeta.crypto.selftest;\n");
    puts("import cajeta.lang.String;\n");
    puts("/**");
    puts(" * Self-signed P-256 TLS fixtures, minted by tools/mint-test-certs.c. The");
    puts(" * keys protect nothing. LOCALHOST and GOOD_TEST run 100 years from minting;");
    puts(" * EXPIRED (CN localhost) ended a year before it.");
    puts(" */");
    puts("final class TestCerts {");
    if (mint("localhost", -3600, 100 * year, "LOCALHOST_CERT", "LOCALHOST_KEY")) return 1;
    putchar('\n');
    if (mint("good.test", -3600, 100 * year, "GOOD_TEST_CERT", "GOOD_TEST_KEY")) return 1;
    putchar('\n');
    if (mint("localhost", -2 * year, -year, "EXPIRED_CERT", "EXPIRED_KEY")) return 1;
    puts("}");
    return 0;
}
