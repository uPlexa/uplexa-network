#include <gtest/gtest.h>
#include <udap/api/messages.hpp>

class APITest : public ::testing::Test
{
 public:
  udap_crypto crypto;
  std::string apiPassword = "password";
  APITest()
  {
    udap_crypto_libsodium_init(&crypto);
  }

  ~APITest()
  {
  }
};

TEST_F(APITest, TestMessageWellFormed)
{
  udap::api::CreateSessionMessage msg;
  msg.msgID     = 0;
  msg.sessionID = 12345;
  msg.CalculateHash(&crypto, apiPassword);
  udap::Info("msghash=", msg.hash);
  ASSERT_TRUE(msg.IsWellFormed(&crypto, apiPassword));
};