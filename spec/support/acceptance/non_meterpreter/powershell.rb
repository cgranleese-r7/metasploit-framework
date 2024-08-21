# TODO: Not sure this should be under Meterpreter long term, but adding here for testing for now

module Acceptance::NonMeterpreter
  POWERSHELL = {
    payloads: [
      {
        name: 'cmd/windows/powershell_reverse_tcp',
        extension: '.ps1',
        platforms: [:windows],
        execute_cmd: ['powershell ${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {
            # Not supported by Windows Meterpreter
            # MeterpreterTryToFork: false,
            # MeterpreterDebugBuild: true
          }
        }
      }
    ],
    module_tests: [
      # TODO: Services is only compatible with `'meterpreter', 'shell', 'powershell'`
      # {
      #   name: 'post/test/services',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Windows only test'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Windows only test'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      {
        name: 'post/test/cmd_exec',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      # {
      #   name: 'post/test/extapi',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      {
        name: 'post/test/file',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: 'post/test/get_env',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      # {
      #   name: 'post/test/meterpreter',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      # {
      #   name: 'post/test/railgun',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      # {
      #   name: 'post/test/railgun_reverse_lookups',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      {
        name: 'post/test/registry',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Windows only test'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Windows only test'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      # {
      #   name: 'post/test/search',
      #   platforms: [
      #     [
      #       :linux,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     [
      #       :osx,
      #       {
      #         skip: true,
      #         reason: 'Payload not compiled for platform'
      #       }
      #     ],
      #     :windows
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # },
      # {
      #   name: 'post/test/unix',
      #   platforms: [
      #     :linux,
      #     :osx,
      #     [
      #       :windows,
      #       {
      #         skip: true,
      #         reason: 'Unix only test'
      #       }
      #     ]
      #   ],
      #   skipped: false,
      #   lines: {
      #     linux: {
      #       known_failures: []
      #     },
      #     osx: {
      #       known_failures: []
      #     },
      #     windows: {
      #       known_failures: []
      #     }
      #   }
      # }
    ]
  }
end
