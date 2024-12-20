package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Type;
import org.locationtech.jts.geom.Point;


import java.awt.*;

@Getter
@Setter
@Entity
@Table(name = "company")
public class Company {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Column(name = "company_name", nullable = false, length = 45)
    private String companyName;

    @Column(name = "company_tel", nullable = false, length = 45)
    private String companyTel;

    @Column(name = "company_location", nullable = false)
    private String companyLocation;

    @Column(name = "company_point", nullable = false, columnDefinition = "POINT")
    private Point companyPoint;

    @Column(name = "company_president_name", nullable = false, length = 45)
    private String companyPresidentName;

    // Getter and Setter
    public Long getCompanyId() {
        return companyId;
    }

    public void setCompanyId(Long companyId) {
        this.companyId = companyId;
    }

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    public String getCompanyTel() {
        return companyTel;
    }

    public void setCompanyTel(String companyTel) {
        this.companyTel = companyTel;
    }

    public String getCompanyLocation() {
        return companyLocation;
    }

    public void setCompanyLocation(String companyLocation) {
        this.companyLocation = companyLocation;
    }

    public Point getCompanyPoint() {
        return companyPoint;
    }

    public void setCompanyPoint(Point companyPoint) {
        this.companyPoint = companyPoint;
    }

    public String getCompanyPresidentName() {
        return companyPresidentName;
    }

    public void setCompanyPresidentName(String companyPresidentName) {
        this.companyPresidentName = companyPresidentName;
    }
}