# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# VULNERABLE: Ruby string interpolation inside an ActiveRecord where clause
# An attacker can supply id=1' OR '1'='1 to bypass query conditions

class User < ApplicationRecord
  def self.find_user(id)
    where("id = '#{id}'")
  end
end
