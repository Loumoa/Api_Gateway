package fr.loumoa.gateway.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.LinkedHashMap;
import java.util.List;

@AllArgsConstructor
public class UserInfos {
    @Getter@Setter
    private int id;
    @Getter@Setter
    private String name;
    @Getter@Setter
    private String email;
    @Getter@Setter
    private List<LinkedHashMap> roles;
}
