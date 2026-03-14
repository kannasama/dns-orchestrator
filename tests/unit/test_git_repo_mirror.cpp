#include "gitops/GitRepoMirror.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

TEST(GitRepoMirrorTest, ConstructorInitializesFields) {
  dns::gitops::GitRepoMirror grm(42, "test-mirror");
  EXPECT_EQ(grm.repoId(), 42);
  EXPECT_EQ(grm.name(), "test-mirror");
}

TEST(GitRepoMirrorTest, InitializeOpensExistingRepo) {
  auto sTmpDir = fs::temp_directory_path() / "grm-test-init";
  fs::remove_all(sTmpDir);
  fs::create_directories(sTmpDir);
  // Pre-create a git repo using git CLI
  std::system(("git init " + sTmpDir.string() + " 2>/dev/null").c_str());

  dns::gitops::GitRepoMirror grm(1, "local-test");
  dns::gitops::GitRepoAuth auth;
  auth.sAuthType = "none";

  EXPECT_NO_THROW(grm.initialize("", sTmpDir.string(), "main", auth));
  fs::remove_all(sTmpDir);
}

TEST(GitRepoMirrorTest, CommitSnapshotWritesFileLocally) {
  auto sTmpDir = fs::temp_directory_path() / "grm-test-commit";
  fs::remove_all(sTmpDir);
  fs::create_directories(sTmpDir);

  // Create git repo with initial commit so HEAD exists
  std::string sSetup =
      "cd " + sTmpDir.string() + " && "
      "git init 2>/dev/null && "
      "git checkout -b main 2>/dev/null && "
      "touch .gitkeep && git add . && "
      "git -c user.name=test -c user.email=t@t commit -m init 2>/dev/null";
  std::system(sSetup.c_str());

  dns::gitops::GitRepoMirror grm(1, "commit-test");
  dns::gitops::GitRepoAuth auth;
  auth.sAuthType = "none";
  grm.initialize("", sTmpDir.string(), "main", auth);

  std::string sContent = R"({"zone":"example.com","records":[]})";
  grm.commitSnapshot("default/example.com.json", sContent, "test commit");

  // Verify the file was written
  fs::path filePath = sTmpDir / "default" / "example.com.json";
  EXPECT_TRUE(fs::exists(filePath));

  std::ifstream ifs(filePath);
  std::string sRead((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
  EXPECT_EQ(sRead, sContent);

  fs::remove_all(sTmpDir);
}
