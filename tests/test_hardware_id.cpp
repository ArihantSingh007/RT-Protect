// tests/test_hardware_id.cpp

#include "licensing/hardware_id.h"
#include "tests/micro_test.h"

using namespace rtprotect::licensing;

MT_TEST(HardwareId_GetLocalFingerprint_ReturnsNonEmptyComponents) {
  auto fp = GetLocalHardwareFingerprint();
  MT_CHECK(!fp.cpu_component.empty());
  MT_CHECK(!fp.storage_component.empty());
  MT_CHECK(!fp.system_component.empty());
  MT_CHECK(!fp.host_component.empty());
  MT_CHECK(fp.composite_id.size() == 64);

  std::string id_str = GetLocalHardwareId();
  MT_CHECK(!id_str.empty());
  MT_CHECK(id_str.find(':') != std::string::npos);
}

MT_TEST(HardwareId_ComputeHardwareSimilarity_ExactMatch) {
  std::string id = "C1:S1:M1:H1-COMPO";
  double score = ComputeHardwareSimilarity(id, id);
  MT_CHECK(score == 1.0);
}

MT_TEST(HardwareId_ComputeHardwareSimilarity_OneComponentChanged_PassesThreshold) {
  // Same CPU, Storage, System GUID, but different Hostname
  std::string id_a = "CPU1:STOR1:SYS1:HOST1-COMPO";
  std::string id_b = "CPU1:STOR1:SYS1:HOST2-COMPO";

  double score = ComputeHardwareSimilarity(id_a, id_b);
  // CPU (0.25) + STOR (0.25) + SYS (0.35) = 0.85
  MT_CHECK(score >= 0.80);
  MT_CHECK(VerifyHardwareMatch(id_a, id_b, 0.75));
}

MT_TEST(HardwareId_ComputeHardwareSimilarity_MultipleComponentsChanged_FailsThreshold) {
  // Different CPU and different Storage and different System
  std::string id_a = "CPUA:STORA:SYSA:HOST1-COMPO";
  std::string id_b = "CPUB:STORB:SYSB:HOST1-COMPO";

  double score = ComputeHardwareSimilarity(id_a, id_b);
  // Only Host matches: 0.15
  MT_CHECK(score < 0.25);
  MT_CHECK(!VerifyHardwareMatch(id_a, id_b, 0.75));
}

MT_TEST(HardwareId_ConfigurableWeights_AdjustsProportionally) {
  std::string id_a = "CPU1:STOR1:SYS1:HOST1-COMPO";
  std::string id_b = "CPU1:STOR2:SYS2:HOST2-COMPO";

  HardwareSimilarityWeights custom;
  custom.cpu_weight = 0.80;
  custom.storage_weight = 0.10;
  custom.system_weight = 0.05;
  custom.host_weight = 0.05;
  custom.min_match_score = 0.70;

  double score = ComputeHardwareSimilarity(id_a, id_b, &custom);
  // CPU (0.80) matches out of total 1.0 = 0.80
  MT_CHECK(score >= 0.79 && score <= 0.81);
  MT_CHECK(VerifyHardwareMatch(id_a, id_b, 0.70, &custom));
}

MT_MAIN()
