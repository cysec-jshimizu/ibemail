COMPILER  = g++
CFLAGS    = -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -std=c++11
LDFLAGS   = -lmcl -lmpzutil
LIBS      = -lgmp -lcrypto
INCLUDE   = -I./include -I/usr/local/include
TARGET    = ./bin/$(shell basename `readlink -f .`)
SRCDIR    = ./source
ifeq "$(strip $(SRCDIR))" ""
  SRCDIR  = .
endif
SOURCES   = $(wildcard $(SRCDIR)/*.cpp)
OBJDIR    = ./obj
ifeq "$(strip $(OBJDIR))" ""
  OBJDIR  = .
endif
OBJECTS   = $(addprefix $(OBJDIR)/, $(notdir $(SOURCES:.cpp=.o)))
DEPENDS   = $(OBJECTS:.o=.d)

$(TARGET): $(OBJECTS) $(LIBS)
	$(COMPILER) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	-mkdir -p $(OBJDIR)
	$(COMPILER) $(CFLAGS) $(INCLUDE) -o $@ -c $<

all: clean $(TARGET)

install:
	install $(SRCDIR)/bb2.hpp ~/.clib/include/bb2.hpp
	ar r $(OBJDIR)/libbb2.a $(OBJECTS) $(OBJDIR)/mpz_util.o
	install -s $(OBJDIR)/libbb2.a ~/.clib/lib/libbb2.a

clean:
	-rm -f $(OBJECTS) $(DEPENDS) $(TARGET)

-include $(DEPENDS)

