{
  'targets': [
    {
      'target_name': 'otrnat',
      'sources': [ "src/otr.cc", "src/userstate.cc" ],
      'libraries': ['-lotr'],
      'library_dirs': [
         '/usr/lib','/usr/local/lib'
      ],
    }
  ]
}
