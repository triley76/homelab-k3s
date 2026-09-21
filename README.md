# Highly Available Kubernetes Platform Lab

A reproducible three-node Kubernetes platform built to explore infrastructure automation, high availability, GitOps, and operational resilience.

This project uses **Packer**, **PowerShell**, **Ansible**, **K3s**, **embedded etcd**, and **kube-vip** to automate the construction of a highly available Kubernetes control plane on VMware. A companion GitOps repository uses **Flux** to manage declarative cluster configuration.

> **Project status:** Core V2 cluster provisioning, three-node control-plane formation, API high availability, controlled node-failure recovery, and Flux reconciliation have been implemented and validated. Additional platform services are being introduced incrementally through GitOps.

## Architecture

```text

                         GitHub

                           |

                           | Flux reconciliation

                           v

                    +---------------+

                    | home-cluster  |

                    | GitOps config |

                    +-------+-------+

                            |

                            v

                Kubernetes Platform Services

 Workstation

 +----------------------------------------------------------+

 |                                                          |

 |  Packer          PowerShell             Ansible          |

 |     |                 |                    |             |

 |     v                 v                    v             |

 | Base Ubuntu VM -> Clone/Discover -> Bootstrap/Configure  |

 |                                                          |

 +---------------------------+------------------------------+

                             |

                             v

             Kubernetes API VIP: 192.0.2.10

                        (kube-vip)

                             |

              +--------------+--------------+

              |              |              |

              v              v              v

          +--------+      +--------+      +--------+

          | k3s01  |      | k3s02  |      | k3s03  |

          | server |      | server |      | server |

          +--------+      +--------+      +--------+

          192.0.2.11      192.0.2.12      192.0.2.13

              \\              |              /

               +-------------+-------------+

                             |

                      embedded etcd
