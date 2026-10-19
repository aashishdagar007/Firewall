#include <gtest/gtest.h>

#include "launch_coordinator.hpp"

namespace fw::gui {

TEST(LaunchCoordinatorTest, StatusesHaveOperatorFacingMessages) {
  EXPECT_STREQ("Protection service is ready.",
               launch_status_message(LaunchStatus::Ready));
  EXPECT_STRNE("", launch_status_message(LaunchStatus::ServiceNotInstalled));
  EXPECT_STRNE("", launch_status_message(LaunchStatus::ServiceStartDenied));
  EXPECT_STRNE("", launch_status_message(LaunchStatus::ServiceStartFailed));
  EXPECT_STRNE("", launch_status_message(LaunchStatus::ServiceStartTimedOut));
  EXPECT_STRNE("", launch_status_message(LaunchStatus::ServiceUnhealthy));
}

#ifndef _WIN32
TEST(LaunchCoordinatorTest, ReportsUnsupportedPlatformOutsideWindows) {
  const LaunchResult result = LaunchCoordinator().ensure_service_ready();
  EXPECT_EQ(LaunchStatus::UnsupportedPlatform, result.status);
  EXPECT_FALSE(result.ready());
}
#endif

}  // namespace fw::gui
