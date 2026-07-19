#pragma once

namespace fw {
namespace gui {

// Spawns the main ImGui window and connects to the IPC server.
// Blocks until the window is closed.
int run_gui();

}
}
