#include "attestation.h"
#include "crypto.h"
#include <openenclave/attestation/sgx/evidence.h>

/*
 * This class generates a singleton containing Crypto and Attestation
 * instances
 */
class Context {
  private:
    Context() {
        m_crypto = new Crypto();
        m_attestation = new Attestation(m_crypto);
    }

  public:
    Attestation *m_attestation;
    Crypto *m_crypto;
    // The format_uuid to use for attestation
    oe_uuid_t format_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

    // Don't forget to declare these two. You want to make sure they
    // are unacceptable otherwise you may accidentally get copies of
    // your singleton appearing.
    Context(Context const &) = delete;
    void operator=(Context const &) = delete;

    static Context &getInstance() {
        static Context instance;
        return instance;
    }
};
