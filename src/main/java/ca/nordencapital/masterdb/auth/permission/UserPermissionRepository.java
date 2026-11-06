package ca.nordencapital.masterdb.auth.permission;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserPermissionRepository extends JpaRepository<UserPermission, UserPermission.Key> {

    @Query("select p from UserPermission p where p.key.userId = :userId")
    List<UserPermission> findByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("delete from UserPermission p where p.key.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);
}
