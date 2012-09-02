#include "ReadlineStream.hpp"

#include <string>
#include <readline/history.h>
#include <readline/readline.h>

using std::string;


ReadlineSource::ReadlineSource(const std::string& prompt)
    : prompt_(prompt)
    , input_(nullptr)
    , currentInput_(nullptr)
    , needToReturnNewline_(false)
{
    rl_bind_key('\t', rl_abort);  // Turn off auto-complete
}


ReadlineSource::ReadlineSource(const ReadlineSource& rhs)
    : prompt_(rhs.prompt_)
    , input_(nullptr)
    , currentInput_(nullptr)
    , needToReturnNewline_(false)
{
}


ReadlineSource::~ReadlineSource()
{
}


std::streamsize ReadlineSource::read(char_type* s, const std::streamsize n)
{
    if (needToReturnNewline_)
    {
        needToReturnNewline_ = false;
        s[0] = '\n';
        return 1;
    }

    // Need to prompt the user for more input
    if (nullptr == input_ || '\0' == *currentInput_)
    {
        free(input_);
        input_ = readline(prompt_.c_str());
        if (nullptr == input_)
        {
            return EOF_;
        }

        add_history(input_);
        currentInput_ = input_;
        needToReturnNewline_ = true;
    }

    std::streamsize copyCount = 0;
    while ('\0' != *currentInput_ && copyCount <= n)
    {
        *s = *currentInput_;
        ++s;
        ++currentInput_;
        ++copyCount;
    }
    return copyCount;
}
