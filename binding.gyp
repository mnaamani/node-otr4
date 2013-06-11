{
  'targets': [
    {
      'target_name': 'otrnat',
      'sources': [ "src/otr.cc", "src/userstate.cc", "src/context.cc", "src/message.cc", "src/privkey.cc", "src/otr-extras.c" ],
      'libraries': ['-lotr'],
      'library_dirs': [
         '/usr/lib','/usr/local/lib'
      ],
    }
  ]
}
