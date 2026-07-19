#include "window.hpp"
#include "ipc_client/ipc_client.hpp"
#include <iostream>
#include <thread>
#include <chrono>

#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

static void glfw_error_callback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << "\n";
}

namespace fw {
namespace gui {

int run_gui() {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;

    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "Aegis XII Firewall Dashboard", NULL, NULL);
    if (window == NULL) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Connect to IPC
    fw::gui::IpcClient ipc;
    
    // Attempt connection immediately, but don't block forever
    bool connected = ipc.connect();

    // UI State
    fw::ipc::StatsPayload live_stats = {0, 0, 0, 0};
    auto last_update = std::chrono::steady_clock::now();

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start the Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // ── Main Dashboard Window ──
        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
        ImGui::Begin("Dashboard", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
        
        ImGui::Text("Aegis XII Firewall");
        ImGui::Separator();

        if (!connected) {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Disconnected from Aegis Service.");
            if (ImGui::Button("Retry Connection")) {
                connected = ipc.connect();
            }
        } else {
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "Connected to Aegis Service via Named Pipe.");
            
            // Poll stats every 1 second
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update).count() >= 1) {
                if (!ipc.get_stats(live_stats)) {
                    connected = false;
                }
                last_update = now;
            }

            ImGui::Spacing();
            ImGui::Text("Active Connections : %u", live_stats.active_connections);
            ImGui::Text("Total Packets      : %llu", live_stats.total_packets);
            ImGui::Text("Blocked Packets    : %llu", live_stats.blocked_packets);
            ImGui::Text("Bytes Transferred  : %llu", live_stats.bytes_transferred);
        }
        
        ImGui::End();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.05f, 0.05f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}

} // namespace gui
} // namespace fw
